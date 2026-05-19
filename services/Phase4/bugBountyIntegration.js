// Phase 4: Bug Bounty Integration - Format for HackerOne, Bugcrowd, etc.
class BugBountyIntegration {
  /**
   * Format report for HackerOne
   */
  static formatForHackerOne(vulnerabilities, programInfo) {
    const report = {
      program_id: programInfo.programId,
      report_body: this._generateHackerOneBody(vulnerabilities),
      vulnerability_information: vulnerabilities.map(vuln => ({
        vulnerability_types: [vuln.type],
        cwe_ids: this._getCWEIds(vuln.type),
        cvss_score: vuln.severity.score,
        priority: this._getPriority(vuln.severity.severity),
        summary: `${vuln.type} in ${vuln.endpoint}`,
        description: this._generateDescription(vuln),
        proof_of_concept: vuln.proof_of_concept?.codeSnippet?.curl || '',
        impact: vuln.impact || 'Potential security breach',
        affected_versions: programInfo.affectedVersions || []
      }))
    };

    return report;
  }

  /**
   * Format report for Bugcrowd
   */
  static formatForBugcrowd(vulnerabilities, programInfo) {
    return {
      submission_type: 'vulnerability',
      severity: this._getBugcrowdSeverity(vulnerabilities),
      title: `Security Issues Found - ${vulnerabilities.length} vulnerabilities`,
      description: this._generateBugcrowdBody(vulnerabilities),
      vulnerabilities: vulnerabilities.map(vuln => ({
        type: vuln.type,
        endpoint: vuln.endpoint,
        parameter: vuln.parameter,
        severity: vuln.severity.severity,
        description: this._generateDescription(vuln),
        remediation: this._getRemediationTips(vuln.type),
        poc: vuln.proof_of_concept?.codeSnippet?.curl || ''
      })),
      impact: this._calculateImpact(vulnerabilities)
    };
  }

  /**
   * Format report for Intigriti
   */
  static formatForIntigriti(vulnerabilities, programInfo) {
    return {
      domain: programInfo.domain,
      submission: {
        title: `Multiple ${vulnerabilities.length} Vulnerabilities Discovered`,
        description: this._generateIntigritiBody(vulnerabilities),
        vulnerabilities: vulnerabilities.map(vuln => ({
          type: vuln.type,
          severity: vuln.severity.severity,
          cvss_score: vuln.severity.score,
          endpoint: vuln.endpoint,
          parameter: vuln.parameter,
          steps: vuln.proof_of_concept?.steps || [],
          impact: vuln.impact || 'Data breach potential',
          remediation: this._getRemediationTips(vuln.type)
        }))
      }
    };
  }

  /**
   * Format report for Synack
   */
  static formatForSynack(vulnerabilities, programInfo) {
    return {
      task_id: programInfo.taskId,
      vulnerabilities: vulnerabilities.map((vuln, index) => ({
        id: index + 1,
        type: vuln.type,
        severity: this._getSynackSeverity(vuln.severity.severity),
        description: this._generateDescription(vuln),
        affected_url: vuln.endpoint,
        affected_parameter: vuln.parameter,
        proof_of_concept: vuln.proof_of_concept,
        remediation: this._getRemediationTips(vuln.type),
        references: this._getReferences(vuln.type)
      })),
      summary: `Found ${vulnerabilities.length} vulnerabilities`
    };
  }

  /**
   * Get CWE IDs for vulnerability type
   */
  static _getCWEIds(vulnType) {
    const cweMappings = {
      'SQLi': ['CWE-89'],
      'XSS': ['CWE-79'],
      'SSRF': ['CWE-918'],
      'XXE': ['CWE-611'],
      'PathTraversal': ['CWE-22'],
      'RCE': ['CWE-78', 'CWE-94'],
      'LFI': ['CWE-22'],
      'AuthBypass': ['CWE-287'],
      'CSRF': ['CWE-352'],
      'PrivilegeEscalation': ['CWE-269'],
      'InfoDisclosure': ['CWE-200'],
      'DoS': ['CWE-400', 'CWE-779']
    };
    return cweMappings[vulnType] || [];
  }

  /**
   * Get priority for HackerOne
   */
  static _getPriority(severity) {
    const priorities = {
      CRITICAL: 'critical',
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
      INFO: 'none'
    };
    return priorities[severity] || 'none';
  }

  /**
   * Get Bugcrowd severity
   */
  static _getBugcrowdSeverity(vulnerabilities) {
    const severities = vulnerabilities.map(v => v.severity.severity);
    if (severities.includes('CRITICAL')) return 'critical';
    if (severities.includes('HIGH')) return 'high';
    if (severities.includes('MEDIUM')) return 'medium';
    return 'low';
  }

  /**
   * Get Synack severity
   */
  static _getSynackSeverity(severity) {
    const mapping = {
      CRITICAL: 'critical',
      HIGH: 'major',
      MEDIUM: 'minor',
      LOW: 'informational',
      INFO: 'informational'
    };
    return mapping[severity] || 'informational';
  }

  /**
   * Generate HackerOne report body
   */
  static _generateHackerOneBody(vulnerabilities) {
    let body = '# Security Vulnerability Report\n\n';
    body += `## Summary\nDiscovered ${vulnerabilities.length} security vulnerabilities during automated security assessment.\n\n`;
    body += '## Vulnerabilities Found\n\n';

    vulnerabilities.forEach((vuln, index) => {
      body += `### ${index + 1}. ${vuln.type}\n`;
      body += `- **Endpoint:** ${vuln.endpoint}\n`;
      body += `- **Parameter:** ${vuln.parameter}\n`;
      body += `- **Severity:** ${vuln.severity.severity}\n`;
      body += `- **Impact:** ${vuln.impact}\n\n`;
    });

    return body;
  }

  /**
   * Generate Bugcrowd report body
   */
  static _generateBugcrowdBody(vulnerabilities) {
    let body = `# Vulnerability Discovery Report\n`;
    body += `**Total Vulnerabilities:** ${vulnerabilities.length}\n\n`;

    vulnerabilities.forEach(vuln => {
      body += `## ${vuln.type}\n`;
      body += `Endpoint: \`${vuln.endpoint}\`\n`;
      body += `Parameter: \`${vuln.parameter}\`\n`;
      body += `Severity: ${vuln.severity.severity}\n\n`;
    });

    return body;
  }

  /**
   * Generate Intigriti report body
   */
  static _generateIntigritiBody(vulnerabilities) {
    let body = `Automated security scan discovered ${vulnerabilities.length} potential vulnerabilities:\n\n`;
    vulnerabilities.forEach(vuln => {
      body += `- ${vuln.type} (${vuln.severity.severity}) on ${vuln.endpoint}\n`;
    });
    return body;
  }

  /**
   * Get remediation tips
   */
  static _getRemediationTips(vulnType) {
    const tips = {
      'SQLi': 'Use parameterized queries and prepared statements',
      'XSS': 'Sanitize and encode all user input',
      'SSRF': 'Validate URLs against whitelist',
      'PathTraversal': 'Validate and normalize file paths',
      'RCE': 'Avoid executing shell commands with user input',
      'XXE': 'Disable DOCTYPE and external entities',
      'AuthBypass': 'Implement proper authentication',
      'CSRF': 'Implement CSRF tokens',
      'PrivilegeEscalation': 'Implement proper access controls',
      'InfoDisclosure': 'Remove sensitive information from responses'
    };
    return tips[vulnType] || 'Implement security controls';
  }

  /**
   * Calculate impact
   */
  static _calculateImpact(vulnerabilities) {
    const critical = vulnerabilities.filter(v => v.severity.severity === 'CRITICAL').length;
    const high = vulnerabilities.filter(v => v.severity.severity === 'HIGH').length;

    if (critical > 0) {
      return `${critical} critical vulnerabilities could lead to complete system compromise`;
    } else if (high > 0) {
      return `${high} high-severity vulnerabilities could lead to data theft or system compromise`;
    }
    return 'Multiple security issues discovered';
  }

  /**
   * Get references
   */
  static _getReferences(vulnType) {
    const references = {
      'SQLi': [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cwe.mitre.org/data/definitions/89.html'
      ],
      'XSS': [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cwe.mitre.org/data/definitions/79.html'
      ],
      'RCE': [
        'https://owasp.org/www-community/attacks/Command_Injection',
        'https://cwe.mitre.org/data/definitions/78.html'
      ]
    };
    return references[vulnType] || [];
  }

  /**
   * Generate description
   */
  static _generateDescription(vuln) {
    return `A ${vuln.type} vulnerability was found in ${vuln.endpoint} affecting the ${vuln.parameter} parameter. This could potentially allow attackers to ${this._getExploitDescription(vuln.type)}.`;
  }

  /**
   * Get exploit description
   */
  static _getExploitDescription(vulnType) {
    const descriptions = {
      'SQLi': 'execute arbitrary SQL queries and access the database',
      'XSS': 'inject malicious scripts into the web application',
      'RCE': 'execute arbitrary code on the server',
      'SSRF': 'access internal resources and services',
      'PathTraversal': 'read arbitrary files from the server',
      'AuthBypass': 'bypass authentication mechanisms',
      'CSRF': 'perform unauthorized actions on behalf of users'
    };
    return descriptions[vulnType] || 'compromise the application security';
  }
}

module.exports = BugBountyIntegration;
