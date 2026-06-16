const fs = require('fs');
const path = require('path');
const askCloudflare = require('./utils/cloudflareFallback');
require('dotenv').config();

class IdorAgent {
  constructor() {
    this.name = 'IDOR / Access Control Agent (Groq / Mistral)';
    this.type = 'Broken Access Control';
    this.apiKey = process.env.GROQ_API_KEY;
    this.logLines = [];
  }

  log(msg) {
    const line = `  [IDOR Agent] ${msg}`;
    console.log(line);
    this.logLines.push(`${new Date().toISOString()} ${line}`);
  }

  async analyze(attackVectors, io = null, scanId = null, sessionCookie = '') {
    this.log(`Starting IDOR analysis...`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'started', vectors: attackVectors.length });

    // Filter for endpoints with numeric parameters
    const idorVectors = attackVectors.filter(v => 
      v.parameter?.name && 
      /id|user|account|order|profile|doc/i.test(v.parameter.name)
    );

    this.log(`Found ${idorVectors.length} potential IDOR vectors out of ${attackVectors.length} total.`);

    if (idorVectors.length === 0) {
      this.log(`No numeric ID vectors found. Skipping IDOR tests.`);
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: 0 });
      return [];
    }

    const targets = idorVectors.slice(0, 5); // Limit tests
    const findings = [];

    // Run probes in parallel
    const testPromises = targets.map(vector => {
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'probing', parameter: vector.parameter?.name, endpoint: vector.endpoint?.url });
      return this.testVector(vector, sessionCookie);
    });
    
    const results = await Promise.allSettled(testPromises);

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) findings.push(r.value);
    }

    this.log(`Analysis complete. Found ${findings.length} IDOR vulnerabilities.`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: findings.length });
    this.saveLog();
    return findings;
  }

  async testVector(vector, sessionCookie = '') {
    const url = vector.endpoint?.url;
    const paramName = vector.parameter?.name;

    if (!url || !paramName) return null;

    try {
      const urlObj = new URL(url);
      let originalValue = urlObj.searchParams.get(paramName);
      let isPathBased = false;

      // --- STRATEGY 1: Query-string parameter (e.g. ?id=5) ---
      // --- STRATEGY 2: Path-segment ID (e.g. /api/user/5) ---
      if (!originalValue || isNaN(originalValue)) {
        // Try to extract a numeric segment from the URL path
        const pathSegments = urlObj.pathname.split('/').filter(Boolean);
        const numericSegment = pathSegments.find(seg => /^\d+$/.test(seg));
        if (numericSegment) {
          originalValue = numericSegment;
          isPathBased = true;
          this.log(`  [IDOR] Found numeric path segment: "${numericSegment}" in ${urlObj.pathname}`);
        } else {
          return null; // No testable numeric ID found anywhere
        }
      }

      const baseId = parseInt(originalValue, 10);
      const testIds = [baseId, baseId + 1, baseId + 2];
      const responses = [];

      for (const id of testIds) {
        let testUrl;
        if (isPathBased) {
          // Replace the numeric segment in the path
          testUrl = url.replace(`/${originalValue}`, `/${id}`);
        } else {
          urlObj.searchParams.set(paramName, id);
          testUrl = urlObj.toString();
        }

        const controller = new AbortController();
        setTimeout(() => controller.abort(), 20000);

        const headers = { 'User-Agent': 'Mozilla/5.0' };
        if (sessionCookie) headers['Cookie'] = sessionCookie;

        const res = await fetch(testUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers
        });

        const body = await res.text();
        responses.push({
          id,
          url: testUrl,
          status: res.status,
          length: body.length,
          bodySnippet: body.substring(0, 500)
        });
      }

      // If both ID+1 and ID+2 returned 200 OK and have different content than baseId, 
      // it's highly likely an IDOR (another user's object was successfully accessed)
      const successResponses = responses.filter(r => r.status === 200);
      
      if (successResponses.length >= 2) {
        // Send to LLM to verify if the structures look like sensitive exposed data
        return await this.askGroq(url, paramName, responses);
      }

    } catch (e) {
      this.log(`Error testing vector ${url}: ${e.message}`);
    }

    return null;
  }

  async askGroq(url, paramName, responses) {
    if (!this.apiKey) return null;

    const prompt = `You are an API security analyst checking for Insecure Direct Object Reference (IDOR).
We tested an endpoint by incrementing a numerical ID parameter.
If changing the ID successfully returned another user's private data (HTTP 200) instead of a 403 Forbidden or 401 Unauthorized, it is an IDOR.

Target Endpoint: ${url}
Parameter: ${paramName}

Test Results:
${JSON.stringify(responses, null, 2)}

Analyze the evidence. If the responses show that different IDs return equally valid data structures (not just generic "Not Found" pages), confirm the IDOR.
Output strict JSON format. If it is NOT an IDOR, return null.

Format:
{
  "finding": true,
  "type": "Broken Access Control",
  "severity": "High",
  "evidence": "Brief description of why the IDOR is confirmed based on the snippets"
}`;

    try {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.1
        })
      });

      const data = await res.json();
      const text = data.choices?.[0]?.message?.content?.trim() || '';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        if (parsed.finding) {
          this.log(`  ✅ IDOR CONFIRMED on parameter ${paramName}`);
          return {
            finding: true,
            type: 'Broken Access Control',
            vulnerabilityType: 'IDOR',
            endpoint: url,
            parameter: paramName,
            payload: `Incrementing ID: ${responses[1].id}`,
            severity: parsed.severity || 'High',
            cvss: 7.5,
            description: `Insecure Direct Object Reference (IDOR) detected. An attacker can access other users' data by changing the ${paramName} numerical value.`,
            proof: parsed.evidence,
            remediation: 'Implement proper object-level authorization checks. Ensure the logged-in user owns the requested object ID.',
            owasp: 'A01:2021 – Broken Access Control',
            testUrl: url
          };
        }
      }
    } catch (e) {
      this.log(`Groq API failed: ${e.message}`);
    }
    return null;
  }

  saveLog() {
    try {
      const logDir = path.join(__dirname, '..', '..', 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      fs.writeFileSync(path.join(logDir, `idor-agent-${Date.now()}.log`), this.logLines.join('\n'));
    } catch (e) {}
  }
}

module.exports = new IdorAgent();
