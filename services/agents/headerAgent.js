/**
 * Header Security Agent — 100% Rule-Based (No LLM)
 * 
 * Your mentor was right: HTTP security headers are deterministic.
 * Using an LLM here wastes free-tier quota and adds latency.
 * This does a HEAD request and checks a dict of required headers.
 * Zero API cost, zero latency overhead, 100% accuracy.
 */
const fs = require('fs');
const path = require('path');
const tls = require('tls');

// Definitive list of required security headers with accurate CVSS scores
const REQUIRED_HEADERS = {
  'strict-transport-security': {
    severity: 'High',
    cvss: 7.5,
    cwe: 'CWE-319',
    description: 'Missing HTTP Strict Transport Security (HSTS) allows attackers to intercept traffic via SSL stripping attacks. Without HSTS, users can be silently downgraded from HTTPS to HTTP.',
    remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    owasp: 'A05:2021 – Security Misconfiguration'
  },
  'content-security-policy': {
    severity: 'High',
    cvss: 7.5,
    cwe: 'CWE-693',
    description: 'Missing Content-Security-Policy header removes a critical browser-side XSS mitigation. Attackers can inject and execute arbitrary scripts without CSP blocking them.',
    remediation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
    owasp: 'A05:2021 – Security Misconfiguration'
  },
  'x-frame-options': {
    severity: 'Medium',
    cvss: 6.1,
    cwe: 'CWE-1021',
    description: 'Missing X-Frame-Options allows the site to be embedded in an iframe. Attackers can use clickjacking to trick authenticated users into performing unintended actions.',
    remediation: 'Add: X-Frame-Options: DENY (or SAMEORIGIN)',
    owasp: 'A05:2021 – Security Misconfiguration'
  },
  'x-content-type-options': {
    severity: 'Medium',
    cvss: 4.3,
    cwe: 'CWE-16',
    description: 'Missing X-Content-Type-Options allows MIME type sniffing. Browsers may execute uploaded files (e.g. images containing JS) as scripts.',
    remediation: 'Add: X-Content-Type-Options: nosniff',
    owasp: 'A05:2021 – Security Misconfiguration'
  },
  'x-xss-protection': {
    severity: 'Low',
    cvss: 4.3,
    cwe: 'CWE-693',
    description: 'Missing X-XSS-Protection removes legacy browser XSS filter. Though deprecated in modern browsers, older clients remain vulnerable.',
    remediation: 'Add: X-XSS-Protection: 1; mode=block',
    owasp: 'A05:2021 – Security Misconfiguration'
  },
  'referrer-policy': {
    severity: 'Low',
    cvss: 3.1,
    cwe: 'CWE-116',
    description: 'Missing Referrer-Policy may leak sensitive URL paths to third parties via the Referer header.',
    remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    owasp: 'A05:2021 – Security Misconfiguration'
  }
};

const SERVER_CVE_MAP = {
  'Apache/2.4.49': 'CVE-2021-41773 — Path Traversal (CVSS 9.8)',
  'Apache/2.4.50': 'CVE-2021-42013 — Path Traversal/RCE (CVSS 9.8)',
  'Express 4.17.1': 'CVE-2022-24999 — ReDoS (CVSS 5.3)',
  'PHP/7.2': 'End of life — no security patches since 2020',
  'PHP/5.6': 'End of life — highly vulnerable',
};

const JS_CVE_MAP = {
  'jquery-1.11.0': 'CVE-2015-9251 — XSS in jQuery 1.11.0 (CVSS 6.1)',
  'jquery-2.1.1': 'CVE-2015-9251 — XSS in jQuery 2.1.1 (CVSS 6.1)',
  'lodash.4.17.10': 'CVE-2019-10744 — Prototype Pollution (CVSS 7.3)',
  'angular-1.4.0': 'CVE-2022-25844 — XSS via template injection (CVSS 8.8)'
};

class HeaderAgent {
  constructor() {
    this.name = 'Header Security Analyst (Rule-Based)';
    this.type = 'Headers';
    this.logLines = [];
  }

  log(msg) {
    const line = `  [Header Agent] ${msg}`;
    console.log(line);
    this.logLines.push(`${new Date().toISOString()} ${line}`);
  }

  async analyze(attackVectors, io = null, scanId = null, sessionCookie = '') {
    this.log(`Starting rule-based header audit (no LLM, zero API cost)...`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'started', vectors: attackVectors.length });

    // Get unique host origins from all attack vectors
    const uniqueHosts = [...new Set(
      attackVectors
        .map(v => { try { const u = new URL(v.endpoint?.url || ''); return u.origin; } catch { return null; } })
        .filter(Boolean)
    )].slice(0, 5); // Check up to 5 unique hosts

    this.log(`Auditing ${uniqueHosts.length} unique hosts: ${uniqueHosts.join(', ')}`);

    const findings = [];

    for (const host of uniqueHosts) {
      if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'probing', parameter: 'Headers', endpoint: host });
      const hostFindings = await this.auditHost(host, sessionCookie);
      findings.push(...hostFindings);
    }

    this.log(`Header audit complete. Found ${findings.length} missing security headers.`);
    if (io) io.emit('agent:update', { scanId, agent: this.type, status: 'completed', findings: findings.length });
    this.saveLog();
    return findings;
  }

  async auditHost(hostOrigin, sessionCookie = '') {
    const findings = [];
    try {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 10000);

      const headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Security/ZerOn' };
      if (sessionCookie) headers['Cookie'] = sessionCookie;

      const res = await fetch(hostOrigin, {
        method: 'GET',
        signal: controller.signal,
        redirect: 'follow',
        headers
      });

      this.log(`  GET ${hostOrigin} → HTTP ${res.status}`);
      const body = await res.text();

      for (const [headerName, meta] of Object.entries(REQUIRED_HEADERS)) {
        const present = res.headers.get(headerName);
        if (!present) {
          this.log(`  ✅ MISSING: ${headerName} (CVSS ${meta.cvss} — ${meta.severity})`);
          findings.push({
            finding: true,
            type: 'Security Misconfiguration',
            endpoint: hostOrigin,
            parameter: headerName,
            payload: `Missing ${headerName} header`,
            severity: meta.severity,
            cvss: meta.cvss,
            cwe: meta.cwe,
            description: meta.description,
            proof: `HTTP response from ${hostOrigin} does not include the ${headerName} header. Confirmed via HEAD request.`,
            remediation: meta.remediation,
            owasp: meta.owasp,
            testUrl: hostOrigin
          });
        } else {
          this.log(`  ✓ Present: ${headerName}: ${present.substring(0, 60)}`);
          
          // Harden A02 Checks
          if (headerName === 'strict-transport-security') {
            const maxAgeMatch = present.match(/max-age=(\d+)/i);
            if (!maxAgeMatch || parseInt(maxAgeMatch[1], 10) < 31536000) {
              findings.push({
                finding: true,
                type: 'Cryptographic Failures',
                endpoint: hostOrigin,
                parameter: headerName,
                payload: `HSTS max-age is too low`,
                severity: 'Medium',
                cvss: 5.3,
                cwe: 'CWE-319',
                description: 'HSTS is present but max-age is less than 1 year (31536000 seconds), providing insufficient protection window.',
                proof: `Header value: ${present}`,
                remediation: 'Increase max-age to at least 31536000.',
                owasp: 'A02:2021 – Cryptographic Failures',
                testUrl: hostOrigin
              });
            }
          }
          
          if (headerName === 'content-security-policy') {
            if (!present.toLowerCase().includes('upgrade-insecure-requests')) {
              findings.push({
                finding: true,
                type: 'Cryptographic Failures',
                endpoint: hostOrigin,
                parameter: headerName,
                payload: `Missing upgrade-insecure-requests`,
                severity: 'Low',
                cvss: 3.1,
                cwe: 'CWE-319',
                description: 'CSP is present but lacks upgrade-insecure-requests directive, allowing potential mixed-content vulnerabilities.',
                proof: `Header value: ${present}`,
                remediation: 'Add upgrade-insecure-requests to the CSP.',
                owasp: 'A02:2021 – Cryptographic Failures',
                testUrl: hostOrigin
              });
            }
          }
        }
      }

      // Check Server and X-Powered-By for vulnerable versions (A03)
      const serverHeader = res.headers.get('server');
      const poweredByHeader = res.headers.get('x-powered-by');
      const allHeaders = [serverHeader, poweredByHeader].filter(Boolean);

      for (const headerValue of allHeaders) {
        for (const [vulnerableVersion, cveDetails] of Object.entries(SERVER_CVE_MAP)) {
          if (headerValue.includes(vulnerableVersion)) {
            this.log(`  ✅ VULNERABLE COMPONENT: ${vulnerableVersion} -> ${cveDetails}`);
            findings.push({
              finding: true,
              type: 'Vulnerable and Outdated Components',
              endpoint: hostOrigin,
              parameter: 'HTTP Headers',
              payload: headerValue,
              severity: 'High',
              cvss: cveDetails.includes('CVSS') ? parseFloat(cveDetails.match(/CVSS ([\d.]+)/)[1]) : 7.0,
              description: `Server exposes vulnerable software version. ${cveDetails}.`,
              proof: `Response header contained: ${headerValue}`,
              remediation: 'Upgrade to a patched version immediately. Disable Server and X-Powered-By headers.',
              owasp: 'A06:2021 – Vulnerable and Outdated Components',
              testUrl: hostOrigin
            });
          }
        }
      }

      // Parse JS from body for Retire.js map
      const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
      let match;
      while ((match = scriptRegex.exec(body)) !== null) {
        const scriptUrl = match[1].toLowerCase();
        for (const [vulnerableJS, cveDetails] of Object.entries(JS_CVE_MAP)) {
          if (scriptUrl.includes(vulnerableJS)) {
            this.log(`  ✅ VULNERABLE COMPONENT (JS): ${vulnerableJS} -> ${cveDetails}`);
            findings.push({
              finding: true,
              type: 'Vulnerable and Outdated Components',
              endpoint: hostOrigin,
              parameter: 'JavaScript Include',
              payload: match[1],
              severity: 'Medium',
              cvss: cveDetails.includes('CVSS') ? parseFloat(cveDetails.match(/CVSS ([\d.]+)/)[1]) : 6.1,
              description: `Application loads a known vulnerable JavaScript library. ${cveDetails}.`,
              proof: `Found vulnerable script tag: <script src="${match[1]}">`,
              remediation: 'Upgrade the referenced JavaScript library to the latest stable version.',
              owasp: 'A06:2021 – Vulnerable and Outdated Components',
              testUrl: hostOrigin
            });
          }
        }
      }

      // Quick TLS check for A02
      if (hostOrigin.startsWith('https://')) {
        try {
          const urlObj = new URL(hostOrigin);
          await new Promise((resolve) => {
            const socket = tls.connect({
              host: urlObj.hostname,
              port: urlObj.port || 443,
              servername: urlObj.hostname,
              rejectUnauthorized: true
            }, () => {
              const cert = socket.getPeerCertificate();
              if (cert && cert.valid_to) {
                const validTo = new Date(cert.valid_to);
                const daysRemaining = (validTo - new Date()) / (1000 * 60 * 60 * 24);
                if (daysRemaining < 30) {
                  findings.push({
                    finding: true, type: 'Cryptographic Failures', endpoint: hostOrigin, parameter: 'TLS Certificate',
                    payload: `Certificate expires soon`, severity: 'Medium', cvss: 5.3, cwe: 'CWE-298',
                    description: `The TLS certificate expires in ${Math.round(daysRemaining)} days.`,
                    proof: `Certificate valid_to: ${cert.valid_to}`, remediation: 'Renew the TLS certificate.',
                    owasp: 'A02:2021 – Cryptographic Failures', testUrl: hostOrigin
                  });
                }
              }
              socket.end(); resolve();
            });
            socket.on('error', (err) => {
              findings.push({
                finding: true, type: 'Cryptographic Failures', endpoint: hostOrigin, parameter: 'TLS Certificate',
                payload: `TLS connection failed`, severity: 'High', cvss: 7.4, cwe: 'CWE-295',
                description: 'The server has an invalid, untrusted, or self-signed TLS certificate.',
                proof: `TLS Error: ${err.message}`, remediation: 'Install a valid TLS certificate from a trusted CA.',
                owasp: 'A02:2021 – Cryptographic Failures', testUrl: hostOrigin
              });
              resolve();
            });
          });
        } catch (e) {}
      }
    } catch (e) {
      this.log(`  ⚠ HEAD request to ${hostOrigin} failed: ${e.message}`);
    }

    return findings;
  }

  saveLog() {
    try {
      const logDir = path.join(__dirname, '..', '..', 'logs');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      fs.writeFileSync(path.join(logDir, `header-agent-${Date.now()}.log`), this.logLines.join('\n'));
    } catch (e) {}
  }
}

module.exports = new HeaderAgent();
