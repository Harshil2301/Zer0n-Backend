// Phase 3: Validator Engine - Confirm exploits are real, not false positives
const ResponseAnalyzer = require('./responseAnalyzer');

class ValidatorEngine {
  /**
   * Validate vulnerability finding
   */
  static async validateVulnerability(testResult) {
    const validation = {
      confirmed: false,
      confidence: 0,
      checks: [],
      recommendation: ''
    };

    // Check 1: Response Analysis
    const responseAnalysis = ResponseAnalyzer.analyzeResponse(
      testResult.response,
      testResult.payload,
      testResult.type
    );

    validation.checks.push({
      name: 'Response Analysis',
      passed: responseAnalysis.vulnerable,
      confidence: responseAnalysis.confidence
    });

    // Check 2: False Positive Detection
    const isFalsePositive = ResponseAnalyzer.detectFalsePositives(
      testResult.response,
      testResult.type
    );

    validation.checks.push({
      name: 'False Positive Check',
      passed: !isFalsePositive,
      confidence: isFalsePositive ? 0 : 100
    });

    // Check 3: Response Consistency
    const isConsistent = this._checkResponseConsistency(testResult);
    validation.checks.push({
      name: 'Response Consistency',
      passed: isConsistent,
      confidence: isConsistent ? 80 : 0
    });

    // Check 4: Contextual Validation
    const contextValid = this._validateContext(testResult);
    validation.checks.push({
      name: 'Contextual Validation',
      passed: contextValid,
      confidence: contextValid ? 70 : 0
    });

    // Calculate overall confidence
    validation.confidence = validation.checks.reduce((sum, check) => 
      sum + (check.passed ? check.confidence : 0), 0
    ) / validation.checks.length;

    // Confirm if confidence > 60%
    validation.confirmed = validation.confidence > 60;

    // Generate recommendation
    validation.recommendation = this._generateRecommendation(validation, testResult);

    return validation;
  }

  /**
   * Check response consistency
   */
  static _checkResponseConsistency(testResult) {
    const response = testResult.response;

    // Should have valid HTTP status
    if (!response.status || response.status < 100 || response.status > 599) {
      return false;
    }

    // Should have response data
    if (!response.data) {
      return false;
    }

    return true;
  }

  /**
   * Validate context-specific behaviors
   */
  static _validateContext(testResult) {
    const { type, response, parameter } = testResult;
    const paramClass = parameter.classification || 'generic';

    // Sensitive parameters shouldn't be vulnerable
    if (parameter.sensitivity === 'critical') {
      return false;
    }

    // Path-like parameters are more likely to have traversal
    if (type === 'PathTraversal' && paramClass === 'path_like') {
      return true;
    }

    // Search parameters are likely to have injection
    if (type === 'SQLi' && paramClass === 'search') {
      return true;
    }

    return true;
  }

  /**
   * Batch validate findings
   */
  static async validateFindings(findings) {
    const validated = [];

    for (const finding of findings) {
      const validation = await this.validateVulnerability(finding);
      if (validation.confirmed) {
        validated.push({
          finding,
          validation
        });
      }
    }

    return validated;
  }

  /**
   * Generate remediation recommendation
   */
  static _generateRecommendation(validation, testResult) {
    const { type } = testResult;
    const recommendations = {
      'SQLi': 'Use parameterized queries or prepared statements. Implement input validation.',
      'XSS': 'Sanitize and escape all user input before rendering. Use Content Security Policy.',
      'SSRF': 'Validate URLs against a whitelist. Disable internal network access.',
      'PathTraversal': 'Validate and normalize file paths. Use whitelisting for allowed files.',
      'RCE': 'Never pass user input to shell commands. Use safe APIs and sandboxing.',
      'XXE': 'Disable DOCTYPE, ENTITY declarations. Use safe XML parsers.',
      'LFI': 'Validate file paths. Implement access controls.',
      'AuthBypass': 'Implement proper authentication mechanisms with secure session handling.',
      'CSRF': 'Implement CSRF tokens. Use SameSite cookie attribute.',
      'PrivilegeEscalation': 'Implement role-based access control. Verify user permissions.'
    };

    if (validation.confidence > 80) {
      return `${recommendations[type]} This finding has high confidence and should be addressed immediately.`;
    } else if (validation.confidence > 60) {
      return `${recommendations[type]} This finding requires further investigation.`;
    } else {
      return `${recommendations[type]} This may be a false positive. Manual verification recommended.`;
    }
  }

  /**
   * Cross-validate with multiple payloads
   */
  static async crossValidate(endpoint, parameter, payloads, type) {
    const results = [];

    for (const payload of payloads) {
      const result = await ResponseAnalyzer.analyzeResponse(
        { data: payload.testResponse },
        payload,
        type
      );

      if (result.vulnerable) {
        results.push(result);
      }
    }

    // If multiple payloads are successful, confidence is higher
    return {
      confirmed: results.length >= 2,
      confidence: Math.min(results.length * 40, 100),
      successfulPayloads: results.length
    };
  }

  /**
   * Request-response pair validation
   */
  static validateRequestResponsePair(request, response, vulnerabilityType) {
    const validation = {
      valid: true,
      issues: []
    };

    // Check if response is relevant to request
    if (!response || typeof response !== 'object') {
      validation.valid = false;
      validation.issues.push('Invalid response format');
    }

    // Check for proper HTTP status codes
    if (response.status < 100 || response.status > 599) {
      validation.valid = false;
      validation.issues.push('Invalid HTTP status code');
    }

    // Check if response time is reasonable
    if (response.timing > 60000) { // 60 seconds
      validation.valid = false;
      validation.issues.push('Response timeout');
    }

    return validation;
  }
}

module.exports = ValidatorEngine;
