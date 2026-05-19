// Phase 4: Report Generator - Create professional vulnerability reports
const PoCGenerator = require('../Phase3/pocGenerator');
const SeverityCalculator = require('../Phase3/severityCalculator');

class ReportGenerator {
  /**
   * Generate comprehensive report
   */
  static generateReport(scanResults, options = {}) {
    const report = {
      metadata: {
        title: 'ZerOn Security Scan Report',
        generated: new Date().toISOString(),
        scannedDomain: options.domain || 'Unknown',
        scanDuration: options.duration || 'N/A',
        version: '1.0.0'
      },
      executive_summary: {},
      vulnerabilities: [],
      statistics: {},
      recommendations: [],
      remediation_priority: []
    };

    // Generate statistics
    report.statistics = this._generateStatistics(scanResults);
    report.executive_summary = this._generateExecutiveSummary(report.statistics);

    // Process vulnerabilities
    scanResults.forEach(finding => {
      const vuln = {
        id: `CVE-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        type: finding.type,
        severity: SeverityCalculator.calculateSimpleSeverity(finding),
        endpoint: finding.endpoint,
        parameter: finding.parameter,
        payload: finding.payload,
        impact: finding.impact || 'Could lead to data breach',
        proof_of_concept: PoCGenerator.generatePoC(finding),
        discovered_date: new Date().toISOString()
      };

      report.vulnerabilities.push(vuln);
    });

    // Sort by severity
    report.vulnerabilities.sort((a, b) => 
      this._severityToScore(b.severity.severity) - this._severityToScore(a.severity.severity)
    );

    // Generate remediation priority
    report.remediation_priority = this._generateRemediationPriority(report.vulnerabilities);
    report.recommendations = this._generateRecommendations(report.vulnerabilities);

    return report;
  }

  /**
   * Generate statistics
   */
  static _generateStatistics(findings) {
    const stats = {
      total_vulnerabilities: findings.length,
      by_severity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
      },
      by_type: {},
      by_endpoint: {}
    };

    findings.forEach(finding => {
      const severity = SeverityCalculator.calculateSimpleSeverity(finding).severity;
      stats.by_severity[severity]++;

      const type = finding.type;
      stats.by_type[type] = (stats.by_type[type] || 0) + 1;

      const endpoint = finding.endpoint;
      stats.by_endpoint[endpoint] = (stats.by_endpoint[endpoint] || 0) + 1;
    });

    return stats;
  }

  /**
   * Generate executive summary
   */
  static _generateExecutiveSummary(stats) {
    const criticalCount = stats.by_severity.CRITICAL;
    const highCount = stats.by_severity.HIGH;
    const totalCount = stats.total_vulnerabilities;

    let riskLevel = 'LOW';
    if (criticalCount > 0) riskLevel = 'CRITICAL';
    else if (criticalCount === 0 && highCount > 0) riskLevel = 'HIGH';
    else if (totalCount > 10) riskLevel = 'MEDIUM';

    return {
      risk_level: riskLevel,
      summary: `This scan discovered ${totalCount} vulnerabilities, including ${criticalCount} critical and ${highCount} high-severity issues.`,
      recommendation: `Immediate remediation is required for ${criticalCount + highCount} critical/high vulnerabilities.`
    };
  }

  /**
   * Generate remediation priority
   */
  static _generateRemediationPriority(vulnerabilities) {
    const priority = [];

    // CRITICAL
    priority.push({
      priority: 1,
      vulnerabilities: vulnerabilities
        .filter(v => v.severity.severity === 'CRITICAL')
        .slice(0, 5),
      deadline: 'IMMEDIATE (within 24 hours)'
    });

    // HIGH
    priority.push({
      priority: 2,
      vulnerabilities: vulnerabilities
        .filter(v => v.severity.severity === 'HIGH')
        .slice(0, 5),
      deadline: 'URGENT (within 7 days)'
    });

    // MEDIUM
    priority.push({
      priority: 3,
      vulnerabilities: vulnerabilities
        .filter(v => v.severity.severity === 'MEDIUM')
        .slice(0, 5),
      deadline: 'SOON (within 30 days)'
    });

    return priority;
  }

  /**
   * Generate recommendations
   */
  static _generateRecommendations(vulnerabilities) {
    const recommendations = [];
    const typeRecommendations = {
      'SQLi': 'Implement parameterized queries and prepared statements',
      'XSS': 'Implement Content Security Policy and output encoding',
      'SSRF': 'Validate all URLs against whitelist',
      'RCE': 'Never pass user input to shell commands',
      'PathTraversal': 'Implement path validation and whitelisting',
      'XXE': 'Disable DOCTYPE and external entities',
      'AuthBypass': 'Implement proper authentication and session management',
      'CSRF': 'Implement CSRF tokens and SameSite cookies'
    };

    const uniqueTypes = [...new Set(vulnerabilities.map(v => v.type))];

    uniqueTypes.forEach(type => {
      recommendations.push({
        type,
        recommendation: typeRecommendations[type] || 'Implement security controls',
        count: vulnerabilities.filter(v => v.type === type).length
      });
    });

    return recommendations;
  }

  /**
   * Generate HTML report
   */
  static generateHTMLReport(report) {
    const severityColors = {
      CRITICAL: '#d32f2f',
      HIGH: '#f57c00',
      MEDIUM: '#fbc02d',
      LOW: '#689f38',
      INFO: '#1976d2'
    };

    let html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>${report.metadata.title}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 8px; margin-bottom: 30px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #667eea; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        h3 { color: #555; margin-top: 20px; margin-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2.5em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; font-size: 0.9em; }
        .severity-badge { display: inline-block; padding: 5px 10px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.85em; }
        .vulnerability { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #ccc; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .vulnerability.critical { border-left-color: ${severityColors.CRITICAL}; }
        .vulnerability.high { border-left-color: ${severityColors.HIGH}; }
        .vulnerability.medium { border-left-color: ${severityColors.MEDIUM}; }
        .vulnerability.low { border-left-color: ${severityColors.LOW}; }
        .code { background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.9em; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th { background: #667eea; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f9f9f9; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>${report.metadata.title}</h1>
            <p>Domain: ${report.metadata.scannedDomain}</p>
            <p>Generated: ${new Date(report.metadata.generated).toLocaleString()}</p>
        </header>

        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">${report.statistics.total_vulnerabilities}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: ${severityColors.CRITICAL};">${report.statistics.by_severity.CRITICAL}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: ${severityColors.HIGH};">${report.statistics.by_severity.HIGH}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: ${severityColors.MEDIUM};">${report.statistics.by_severity.MEDIUM}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>

        <h3>Risk Assessment</h3>
        <p><strong>Overall Risk Level:</strong> <span class="severity-badge" style="background-color: ${severityColors[report.executive_summary.risk_level]}">${report.executive_summary.risk_level}</span></p>
        <p>${report.executive_summary.summary}</p>
        <p><strong>Recommendation:</strong> ${report.executive_summary.recommendation}</p>

        <h2>Vulnerabilities by Severity</h2>`;

    // Vulnerabilities
    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].forEach(severity => {
      const vulns = report.vulnerabilities.filter(v => v.severity.severity === severity);
      if (vulns.length > 0) {
        html += `<h3>${severity} Severity (${vulns.length})</h3>`;
        vulns.forEach(vuln => {
          html += `
        <div class="vulnerability ${severity.toLowerCase()}">
            <h4>${vuln.type} - ${vuln.endpoint}</h4>
            <p><strong>Parameter:</strong> ${vuln.parameter}</p>
            <p><strong>Severity Score:</strong> ${vuln.severity.score}/10</p>
            <p><strong>Impact:</strong> ${vuln.impact}</p>
            <h4>Proof of Concept:</h4>
            <div class="code">${vuln.proof_of_concept.codeSnippet?.curl || 'N/A'}</div>
        </div>`;
        });
      }
    });

    html += `
        <h2>Remediation Recommendations</h2>
        <table>
            <tr>
                <th>Vulnerability Type</th>
                <th>Count</th>
                <th>Recommendation</th>
            </tr>`;

    report.recommendations.forEach(rec => {
      html += `
            <tr>
                <td>${rec.type}</td>
                <td>${rec.count}</td>
                <td>${rec.recommendation}</td>
            </tr>`;
    });

    html += `
        </table>

        <div class="footer">
            <p>This report was automatically generated by ZerOn Vulnerability Scanner</p>
            <p>For security concerns, please contact your security team immediately</p>
        </div>
    </div>
</body>
</html>`;

    return html;
  }

  /**
   * Convert severity to score
   */
  static _severityToScore(severity) {
    const scores = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 0 };
    return scores[severity] || 0;
  }
}

module.exports = ReportGenerator;
