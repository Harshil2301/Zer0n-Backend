// Phase 1: Static Analysis Service - Code analysis integration
const axios = require('axios');

class StaticAnalysisService {
  /**
   * Analyze code for vulnerabilities
   */
  static async analyzeCode(codeContent, language = 'javascript') {
    const vulnerabilities = [];

    try {
      // Check for common vulnerabilities
      this._checkSQLInjection(codeContent, vulnerabilities);
      this._checkXSS(codeContent, vulnerabilities);
      this._checkPathTraversal(codeContent, vulnerabilities);
      this._checkCommandInjection(codeContent, vulnerabilities);
      this._checkHardcodedSecrets(codeContent, vulnerabilities);
      this._checkInsecureCrypto(codeContent, vulnerabilities);
      this._checkInsecureDeserialization(codeContent, vulnerabilities);
      this._checkXXE(codeContent, vulnerabilities);

      return {
        success: true,
        language,
        vulnerabilityCount: vulnerabilities.length,
        vulnerabilities
      };
    } catch (error) {
      console.error('Static analysis error:', error);
      return {
        success: false,
        error: error.message,
        vulnerabilities
      };
    }
  }

  /**
   * Check for SQL injection patterns
   */
  static _checkSQLInjection(code, vulnerabilities) {
    // Look for string concatenation in SQL queries
    const patterns = [
      /query\s*=\s*['"](.*?)\s*\+\s*(.*?)['"]/gi,
      /sql\s*=\s*['"](.*?)\s*\+\s*(.*?)['"]/gi,
      /exec\s*\(\s*['"](SELECT|INSERT|UPDATE|DELETE).*?\+/gi,
      /db\.execute\s*\(\s*['"](SELECT|INSERT|UPDATE|DELETE).*?\+/gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        matches.forEach(match => {
          vulnerabilities.push({
            type: 'SQL Injection',
            severity: 'HIGH',
            pattern: match,
            line: code.split('\n').findIndex(line => line.includes(match)),
            remediation: 'Use parameterized queries or prepared statements'
          });
        });
      }
    });
  }

  /**
   * Check for XSS vulnerabilities
   */
  static _checkXSS(code, vulnerabilities) {
    const patterns = [
      /innerHTML\s*=\s*.*?req\.|innerHTML\s*=\s*.*?input|innerHTML\s*=\s*.*?user/gi,
      /eval\s*\(\s*.*?req\.|eval\s*\(\s*.*?input/gi,
      /\.html\s*\(\s*.*?req\.|\.html\s*\(\s*.*?input/gi,
      /dangerouslySetInnerHTML/gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        matches.forEach(match => {
          vulnerabilities.push({
            type: 'Cross-Site Scripting (XSS)',
            severity: 'HIGH',
            pattern: match,
            remediation: 'Sanitize and escape all user input before rendering'
          });
        });
      }
    });
  }

  /**
   * Check for path traversal
   */
  static _checkPathTraversal(code, vulnerabilities) {
    const patterns = [
      /readFile\s*\(\s*['"](.*?)"\s*\+\s*(.*?)\)/gi,
      /readFileSync\s*\(\s*.*?path\)/gi,
      /fs\.read.*\(\s*.*?req\.|fs\.read.*\(\s*.*?input/gi,
      /__dirname\s*\+\s*['"]\.\.\//gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        vulnerabilities.push({
          type: 'Path Traversal',
          severity: 'HIGH',
          remediation: 'Validate and sanitize file paths using whitelists'
        });
      }
    });
  }

  /**
   * Check for command injection
   */
  static _checkCommandInjection(code, vulnerabilities) {
    const patterns = [
      /exec\s*\(\s*['"](.*?)"\s*\+\s*(.*?)\)/gi,
      /spawn\s*\(\s*['"](.*?)"\s*,\s*\[.*?req\.|spawn\s*\(\s*['"](.*?)"\s*,\s*\[.*?input/gi,
      /child_process\.exec\s*\(\s*.*?req\./gi,
      /os\.system\s*\(\s*.*?input/gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        vulnerabilities.push({
          type: 'Command Injection',
          severity: 'CRITICAL',
          remediation: 'Never pass user input to shell commands. Use safe APIs.'
        });
      }
    });
  }

  /**
   * Check for hardcoded secrets
   */
  static _checkHardcodedSecrets(code, vulnerabilities) {
    const patterns = [
      /password\s*=\s*['"](.*?)['"]/gi,
      /api[_-]?key\s*=\s*['"](.*?)['"]/gi,
      /secret\s*=\s*['"](.*?)['"]/gi,
      /token\s*=\s*['"](.*?)['"]/gi,
      /private[_-]?key\s*=\s*['"](.*?)['"]/gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        vulnerabilities.push({
          type: 'Hardcoded Secrets',
          severity: 'CRITICAL',
          remediation: 'Store secrets in environment variables or secure vaults'
        });
      }
    });
  }

  /**
   * Check for insecure cryptography
   */
  static _checkInsecureCrypto(code, vulnerabilities) {
    const patterns = [
      /md5\s*\(/gi,
      /sha1\s*\(/gi,
      /DES\s*\(/gi,
      /RC4\s*\(/gi,
      /crypto\.cipher\s*\(['"](des|md5|sha1)/gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        vulnerabilities.push({
          type: 'Insecure Cryptography',
          severity: 'MEDIUM',
          remediation: 'Use strong algorithms like AES-256, SHA-256, or bcrypt'
        });
      }
    });
  }

  /**
   * Check for insecure deserialization
   */
  static _checkInsecureDeserialization(code, vulnerabilities) {
    const patterns = [
      /unserialize\s*\(/gi,
      /pickle\.loads\s*\(/gi,
      /JSON\.parse\s*\(\s*.*?eval/gi,
      /jQuery\.parseJSON/gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        vulnerabilities.push({
          type: 'Insecure Deserialization',
          severity: 'HIGH',
          remediation: 'Validate and sanitize all deserialized data'
        });
      }
    });
  }

  /**
   * Check for XXE vulnerabilities
   */
  static _checkXXE(code, vulnerabilities) {
    const patterns = [
      /XMLParser\s*\(/gi,
      /parseXml\s*\(/gi,
      /DOCTYPE\s/gi,
      /ENTITY/gi
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        vulnerabilities.push({
          type: 'XXE Injection',
          severity: 'HIGH',
          remediation: 'Disable DOCTYPE declarations and external entities in XML parsers'
        });
      }
    });
  }

  /**
   * Generate SAST report
   */
  static generateSASTReport(analysisResults) {
    const report = {
      timestamp: new Date(),
      totalVulnerabilities: analysisResults.vulnerabilities.length,
      bySeverity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
      },
      vulnerabilities: analysisResults.vulnerabilities
    };

    analysisResults.vulnerabilities.forEach(vuln => {
      report.bySeverity[vuln.severity]++;
    });

    return report;
  }
}

module.exports = StaticAnalysisService;
