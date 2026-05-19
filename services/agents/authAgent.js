const fs = require('fs');
const path = require('path');
require('dotenv').config();

class AuthAgent {
  constructor() {
    this.name = 'Auth Security Analyst (Mistral)';
    this.type = 'Auth Failures';
    this.apiKey = process.env.MISTRAL_API_KEY;
    this.logLines = [];
  }

  log(msg) {
    const line = `  [Auth Agent] ${msg}`;
    console.log(line);
    this.logLines.push(`${new Date().toISOString()} ${line}`);
  }

  async analyze(attackVectors, io = null, scanId = null, sessionCookie = '') {
    this.log(`Starting A07 Auth Failures analysis...`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'started', vectors: attackVectors.length });

    // Filter to only login/auth endpoints
    const authVectors = attackVectors.filter(v => 
      ['uid', 'username', 'email', 'user', 'password', 'pass'].includes(v.parameter?.name?.toLowerCase()) ||
      (v.endpoint?.url || '').toLowerCase().includes('login') ||
      (v.endpoint?.url || '').toLowerCase().includes('auth')
    );

    this.log(`Found ${authVectors.length} auth-related vectors out of ${attackVectors.length} total.`);

    if (authVectors.length === 0) {
      this.log(`No auth vectors found. Skipping Auth tests.`);
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: 0 });
      return [];
    }

    const targets = authVectors.slice(0, 5); // Limit tests
    const findings = [];

    // Run probes in parallel
    const testPromises = targets.map(vector => {
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'probing', parameter: vector.parameter?.name, endpoint: vector.endpoint?.url });
      return this.testVector(vector, sessionCookie);
    });
    
    const results = await Promise.allSettled(testPromises);

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) findings.push(...r.value);
    }

    // Step 2: Test unauthenticated access to admin panels
    const adminFindings = await this.testAdminAccess(targets[0]?.endpoint, sessionCookie);
    if (adminFindings) findings.push(...adminFindings);

    this.log(`Analysis complete. Found ${findings.length} Auth Failures.`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: findings.length });
    this.saveLog();
    return findings;
  }

  async testVector(vector, sessionCookie = '') {
    const findings = [];
    const url = vector.endpoint?.url;
    const paramName = vector.parameter?.name || 'username';

    if (!url) return findings;

    // We will collect multiple response patterns to send to Mistral
    const responsePatterns = [];

    const authTests = [
      { user: 'admin', pass: 'admin', desc: 'Default Creds' },
      { user: 'admin', pass: 'password', desc: 'Default Creds' },
      { user: 'nonexistent_user_12345', pass: 'wrongpass', desc: 'Enum Check 1' },
      { user: 'admin', pass: 'wrongpass', desc: 'Enum Check 2' }
    ];

    for (const test of authTests) {
      try {
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 10000);

        const res = await fetch(url, {
          method: 'POST',
          redirect: 'manual', // Catch redirects and headers
          signal: controller.signal,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0',
            ...(sessionCookie ? { 'Cookie': sessionCookie } : {})
          },
          body: `${paramName}=${encodeURIComponent(test.user)}&passw=${encodeURIComponent(test.pass)}&password=${encodeURIComponent(test.pass)}&btnSubmit=Login&submit=Login`
        });
        
        const body = await res.text();
        const headersStr = Array.from(res.headers.entries()).map(e => `${e[0]}: ${e[1]}`).join('\\n');
        
        responsePatterns.push({
          test: test.desc,
          credentials: `${test.user}:${test.pass}`,
          status: res.status,
          headers: headersStr,
          bodySnippet: body.substring(0, 500) // First 500 chars for LLM context
        });
      } catch (e) {
        this.log(`Error testing vector ${url}: ${e.message}`);
      }
    }

    if (responsePatterns.length === 0) return findings;

    // Send to Mistral
    const mistralFindings = await this.askMistral(url, paramName, responsePatterns);
    return mistralFindings;
  }

  async askMistral(url, paramName, responsePatterns) {
    if (!this.apiKey) {
      this.log(`MISTRAL_API_KEY missing, skipping Mistral reasoning.`);
      return [];
    }

    const prompt = `You are an authentication security analyst.
Given these login endpoints and response patterns, identify:
1. Default credential acceptance (admin/admin, admin/password, root/root)
2. Username enumeration via different error messages
3. Missing account lockout (same credentials accepted 10+ times)
4. JWT/session token weaknesses in response headers

Target Endpoint: ${url}
Parameter: ${paramName}

Test Results:
${JSON.stringify(responsePatterns, null, 2)}

Analyze the evidence and output strict JSON with finding type, evidence, and severity. 
Return an array of finding objects. If no vulnerabilities are found, return an empty array [].
Output ONLY valid JSON array. Do not include markdown blocks like \`\`\`json.

Format:
[
  {
    "type": "Auth Failures",
    "subtype": "Default Credentials" | "Username Enumeration" | "Session Weakness",
    "severity": "High" | "Medium" | "Low",
    "evidence": "Brief description of the proof"
  }
]`;

    try {
      const response = await fetch('https://api.mistral.ai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: 'mistral-large-latest',
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.2,
          response_format: { type: "json_object" }
        })
      });

      if (response.status === 429) {
        throw new Error('Mistral Rate Limit Exceeded (429)');
      }

      if (!response.ok) {
        throw new Error(`Mistral API Error ${response.status}: ${await response.text()}`);
      }

      const data = await response.json();
      let content = data.choices[0].message.content.trim();
      
      // Clean up markdown if Mistral ignored instructions
      if (content.startsWith('\`\`\`json')) {
        content = content.replace(/\`\`\`json/g, '').replace(/\`\`\`/g, '').trim();
      }

      // Handle both { "findings": [...] } and [...]
      let parsed = JSON.parse(content);
      if (parsed.findings) parsed = parsed.findings;
      if (!Array.isArray(parsed)) parsed = [parsed];

      const findings = parsed.map(f => ({
        finding: true,
        type: 'Auth Failures',
        vulnerabilityType: f.subtype || 'Auth Failures',
        endpoint: url,
        parameter: paramName,
        payload: 'Auth Tests',
        severity: f.severity || 'High',
        cvss: f.severity === 'High' ? 8.5 : 5.0,
        description: `Authentication vulnerability detected: ${f.subtype}. ${f.evidence}`,
        proof: f.evidence,
        remediation: 'Implement proper authentication controls, generic error messages, and strong session management per OWASP recommendations.',
        owasp: 'A07:2021 – Identification and Authentication Failures',
        testUrl: url
      }));

      return findings;
    } catch (e) {
      this.log(`Mistral API failed: ${e.message}`);
      return [];
    }
  }

  async testAdminAccess(endpoint, sessionCookie = '') {
    if (!endpoint || !endpoint.url) return [];
    try {
      const urlObj = new URL(endpoint.url);
      const host = urlObj.origin;
      const adminPaths = ['/admin', '/dashboard', '/panel', '/administrator'];
      const findings = [];
      
      for (const path of adminPaths) {
        const testUrl = `${host}${path}`;
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 5000);
        
        const headers = {};
        if (sessionCookie) headers['Cookie'] = sessionCookie;

        const res = await fetch(testUrl, {
          method: 'GET',
          redirect: 'manual', 
          signal: controller.signal,
          headers
        });
        
        if (res.status === 200) {
          const body = await res.text();
          const adminKeywords = ['admin', 'dashboard', 'settings', 'users'];
          const loginKeywords = ['login', 'sign in', 'password'];
          
          const hasAdmin = adminKeywords.some(k => body.toLowerCase().includes(k));
          const hasLogin = loginKeywords.some(k => body.toLowerCase().includes(k));
          
          if (hasAdmin && !hasLogin) {
            findings.push({
              finding: true,
              type: 'Auth Failures',
              vulnerabilityType: 'Unauthenticated Admin Access',
              endpoint: testUrl,
              parameter: 'Path',
              payload: testUrl,
              severity: 'High',
              cvss: 7.5,
              description: 'Unauthenticated administrative access confirmed. The path returned HTTP 200 and exposed sensitive administrative functionality without authentication.',
              proof: `Unauthenticated HTTP GET request to ${testUrl} returned 200 OK with admin content.`,
              testUrl: testUrl
            });
          }
        }
      }
      return findings;
    } catch(e) {
      return [];
    }
  }

  saveLog() {
    try {
      const logDir = path.join(__dirname, '..', '..', 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      fs.writeFileSync(path.join(logDir, `auth-agent-${Date.now()}.log`), this.logLines.join('\\n'));
    } catch (e) {}
  }
}

module.exports = new AuthAgent();
