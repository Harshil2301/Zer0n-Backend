const RagMemory = require('./ragMemory');
const fs = require('fs');
const path = require('path');
const askCloudflare = require('./utils/cloudflareFallback');
require('dotenv').config();

// FIX #4/#5: Configurable vector cap — no silent drops
const MAX_VECTORS = 30;

class XssAgent {
  constructor() {
    this.name = 'XSS Expert (Groq Llama 70B)';
    this.type = 'XSS';
    this.apiKey = process.env.GROQ_API_KEY;
    this.logLines = [];
  }

  log(msg) {
    const line = `  [XSS Agent] ${msg}`;
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
      console.warn(`[XSS Agent] ⚠️ Attack surface capped at ${MAX_VECTORS} vectors — ${skipped} vectors skipped. Consider increasing MAX_VECTORS for full coverage.`);
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

    this.log(`Analysis complete. Found ${findings.length} XSS vulnerabilities.`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: findings.length });
    this.saveLog();
    return findings;
  }

  async testVector(vector, ragContext, sessionCookie = '') {
    const { endpoint, parameter } = vector;
    if (!endpoint?.url || !parameter?.name) return null;

    this.log(`Testing ${endpoint.url} [param: ${parameter.name}]`);

    // Step 1: Ask Groq to generate 6 intelligent XSS payloads
    const payloads = await this.generatePayloads(endpoint.url, parameter.name, ragContext);
    this.log(`  → Groq generated ${payloads.length} payloads for [${parameter.name}]: ${payloads.slice(0, 2).join(' | ')}...`);

    // Step 2: Fire all payloads in parallel
    const httpPromises = payloads.map(payload => this.firePayload(endpoint, parameter.name, payload, sessionCookie));
    const responses = await Promise.allSettled(httpPromises);

    // Step 3: Check real responses for XSS reflection
    for (let i = 0; i < responses.length; i++) {
      if (responses[i].status !== 'fulfilled' || !responses[i].value) continue;
      const { url: testUrl, status, body, payload } = responses[i].value;

      // FIX #2: Multi-layer XSS confirmation to eliminate false positives
      //
      // Layer 1: Payload must appear literally in the raw response body
      const isLiterallyPresent = body.includes(payload);

      if (!isLiterallyPresent) {
        this.log(`  ↳ Payload ${i + 1}/${payloads.length}: "${payload.substring(0,30)}..." → HTTP ${status} — not reflected`);
        continue;
      }

      // Layer 2: Reject if the payload is HTML-entity-encoded in the response
      // e.g. <script> becoming &lt;script&gt; means the server IS escaping it → NOT vulnerable
      const htmlEncodedPayload = payload
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
      
      const isHtmlEncoded = body.includes(htmlEncodedPayload);
      if (isHtmlEncoded) {
        this.log(`  ↳ Payload ${i + 1}/${payloads.length}: "${payload.substring(0,30)}..." → reflected BUT HTML-encoded → NOT vulnerable (server is escaping correctly)`);
        continue;
      }

      // Layer 3: The payload must appear in a context that would execute
      // Check that it appears outside of a comment or a plain text node
      const payloadIndex = body.indexOf(payload);
      const snippetBefore = body.substring(Math.max(0, payloadIndex - 50), payloadIndex);
      
      // If the payload is inside an HTML comment (<!-- ... -->), it won't execute
      const insideComment = snippetBefore.includes('<!--') && !snippetBefore.includes('-->');
      if (insideComment) {
        this.log(`  ↳ Payload ${i + 1}/${payloads.length}: "${payload.substring(0,30)}..." → reflected inside HTML comment → NOT executable`);
        continue;
      }

      // All checks passed — confirmed reflected XSS
      this.log(`  ✅ XSS CONFIRMED! Payload "${payload}" found unencoded in server response (not in comment)`);
      return {
        finding: true,
        type: 'Cross-Site Scripting (XSS)',
        endpoint: endpoint.url,
        parameter: parameter.name,
        payload,
        severity: 'High',
        cvss: 6.1,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        cwe: 'CWE-79',
        owasp: 'A03:2021 – Injection',
        description: `Reflected XSS confirmed on parameter "${parameter.name}". Payload "${payload}" was returned unescaped in the server HTML response. Attackers can steal session cookies, redirect victims, or execute arbitrary JavaScript in their browser.`,
        proof: this.extractReflectedContext(body, payload),
        remediation: 'HTML-encode all user input before rendering it in responses (use htmlspecialchars in PHP, DOMPurify in JS). Implement a strict Content-Security-Policy (CSP) header to block inline script execution.',
        testUrl
      };
    }

    return null;
  }

  async generatePayloads(url, paramName, ragContext) {
    const prompt = `You are an elite XSS pentester. Generate exactly 6 different XSS payloads for this target.

Target URL: ${url}
Vulnerable Parameter: ${paramName}
${ragContext}

Generate payloads covering these attack categories:
1. Classic script injection
2. Image onerror handler
3. SVG onload injection
4. Attribute injection (closing a tag first)
5. HTML entity/encoding bypass
6. Input field context (for form parameters)

Return ONLY a valid JSON array of 6 payload strings. No explanation. Example:
["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "\"><script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;", "' onmouseover='alert(1)"]`;

    try {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: [{ role: 'user', content: prompt }],
          max_tokens: 250,
          temperature: 0.2
        })
      });
      if (res.status === 429) throw new Error('429 Rate Limit');
      const data = await res.json();
      const text = data.choices?.[0]?.message?.content?.trim() || '[]';
      const jsonStr = text.match(/\[[\s\S]*\]/)?.[0] || '[]';
      const parsed = JSON.parse(jsonStr);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed.slice(0, 6);
    } catch (e) {
      this.log(`  ⚠ Groq payload generation failed (${e.message}), falling back to Cloudflare AI`);
      try {
        const text = await askCloudflare(prompt);
        const jsonStr = text.match(/\[[\s\S]*\]/)?.[0] || '[]';
        const parsed = JSON.parse(jsonStr);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed.slice(0, 6);
      } catch (cfErr) {
        this.log(`  ⚠ Cloudflare fallback also failed: ${cfErr.message}`);
      }
    }

    // Intelligent fallback payloads
    return [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '"><script>alert(1)</script>',
      "' onmouseover='alert(1)",
      '<iframe src=javascript:alert(1)>'
    ];
  }

  async firePayload(endpoint, paramName, payload, sessionCookie = '') {
    try {
      const testUrl = this.buildUrl(endpoint.url, paramName, payload);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const opts = {
        signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Accept': 'text/html,*/*' }
      };
      if (sessionCookie) {
        opts.headers['Cookie'] = sessionCookie;
      }

      let res;
      if (endpoint.method === 'POST') {
        res = await fetch(endpoint.url, {
          ...opts,
          method: 'POST',
          body: `${paramName}=${encodeURIComponent(payload)}`,
          headers: { ...opts.headers, 'Content-Type': 'application/x-www-form-urlencoded' }
        });
      } else {
        res = await fetch(testUrl, { ...opts, method: 'GET' });
      }
      clearTimeout(timeout);
      const body = await res.text();
      return { url: testUrl, status: res.status, body, payload };
    } catch (e) {
      return null;
    }
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

  extractReflectedContext(body, payload) {
    const idx = body.toLowerCase().indexOf(payload.toLowerCase().substring(0, 10));
    if (idx === -1) return body.substring(0, 300);
    const start = Math.max(0, idx - 100);
    const end = Math.min(body.length, idx + payload.length + 100);
    return `...${body.substring(start, end)}...`;
  }

  saveLog() {
    try {
      const logDir = path.join(__dirname, '..', '..', 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      fs.writeFileSync(
        path.join(logDir, `xss-agent-${Date.now()}.log`),
        this.logLines.join('\n')
      );
    } catch (e) {}
  }
}

module.exports = new XssAgent();
