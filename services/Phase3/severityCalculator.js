// Phase 3: Severity Calculator - CVSS scoring
class SeverityCalculator {
  /**
   * Calculate CVSS v3.1 score
   */
  static calculateCVSS(vulnerability) {
    let score = 0;

    // Base Score Calculation
    const av = this._parseAV(vulnerability.attack_vector || 'NETWORK');
    const au = this._parseAU(vulnerability.attack_complexity || 'LOW');
    const pr = this._parsePR(vulnerability.privileges_required || 'NONE');
    const ui = this._parseUI(vulnerability.user_interaction || 'NONE');
    const s = this._parseS(vulnerability.scope || 'UNCHANGED');
    const c = this._parseC(vulnerability.confidentiality || 'NONE');
    const i = this._parseI(vulnerability.integrity || 'NONE');
    const a = this._parseA(vulnerability.availability || 'NONE');

    // Calculate impact
    const impact = 1 - ((1 - c) * (1 - i) * (1 - a));

    // Calculate exploitability
    const exploitability = 8.22 * av * au * pr * ui;

    // Calculate base score
    let baseScore;
    if (impact <= 0) {
      baseScore = 0;
    } else if (s === 1) {
      baseScore = Math.min(6.42 * impact + exploitability, 10);
    } else {
      baseScore = Math.min((impact + exploitability) * 1.08, 10);
    }

    score = Math.round(baseScore * 10) / 10;

    return {
      score,
      severity: this._getSeverityRating(score),
      vector: `CVSS:3.1/AV:${this._encodeAV(av)}/AC:${this._encodeAU(au)}/PR:${this._encodePR(pr)}/UI:${this._encodeUI(ui)}/S:${s === 1 ? 'C' : 'U'}/C:${this._encodeC(c)}/I:${this._encodeI(i)}/A:${this._encodeA(a)}`
    };
  }

  /**
   * Simple severity calculation
   */
  static calculateSimpleSeverity(vulnerability) {
    const { type, impact, auth, complexity } = vulnerability;

    let score = 0;

    // Base vulnerability type scores
    const typeScores = {
      'RCE': 90,
      'Remote Code Execution': 90,
      'AuthBypass': 85,
      'Authentication Bypass': 85,
      'PrivilegeEscalation': 80,
      'SQLi': 80,
      'SQL Injection': 80,
      'IDOR': 75,
      'XXE': 75,
      'SSRF': 75,
      'Business Logic Flaw': 70,
      'PathTraversal': 70,
      'LFI': 70,
      'CORS Misconfiguration': 65,
      'XSS': 60,
      'Cross-Site Scripting': 60,
      'Open Redirect': 50,
      'CSRF': 50,
      'DoS': 40,
      'InfoDisclosure': 30,
      'Information Disclosure': 30
    };

    score = typeScores[type] || 50;

    // Adjust for impact
    if (impact === 'high') score += 15;
    else if (impact === 'medium') score += 5;
    else if (impact === 'low') score -= 5;

    // Adjust for authentication
    if (auth === 'none') score += 10;
    else if (auth === 'low') score += 5;
    else score -= 5;

    // Adjust for complexity
    if (complexity === 'low') score += 10;
    else if (complexity === 'high') score -= 15;

    score = Math.max(0, Math.min(100, score));

    return {
      score,
      severity: this._getSeverityRating(score)
    };
  }

  /**
   * Get severity rating
   */
  static _getSeverityRating(score) {
    if (score >= 90) return 'CRITICAL';
    if (score >= 70) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'INFO';
  }

  /**
   * Parse attack vector
   */
  static _parseAV(av) {
    const values = {
      'NETWORK': 0.85,
      'ADJACENT': 0.62,
      'LOCAL': 0.55,
      'PHYSICAL': 0.2
    };
    return values[av] || 0.85;
  }

  /**
   * Parse attack complexity
   */
  static _parseAU(ac) {
    return ac === 'LOW' ? 0.77 : 0.44;
  }

  /**
   * Parse privileges required
   */
  static _parsePR(pr) {
    const values = { 'NONE': 0.85, 'LOW': 0.62, 'HIGH': 0.27 };
    return values[pr] || 0.85;
  }

  /**
   * Parse user interaction
   */
  static _parseUI(ui) {
    return ui === 'NONE' ? 0.85 : 0.62;
  }

  /**
   * Parse scope
   */
  static _parseS(s) {
    return s === 'CHANGED' ? 1 : 0;
  }

  /**
   * Parse confidentiality
   */
  static _parseC(c) {
    const values = { 'NONE': 0, 'LOW': 0.22, 'HIGH': 0.56 };
    return values[c] || 0;
  }

  /**
   * Parse integrity
   */
  static _parseI(i) {
    const values = { 'NONE': 0, 'LOW': 0.22, 'HIGH': 0.56 };
    return values[i] || 0;
  }

  /**
   * Parse availability
   */
  static _parseA(a) {
    const values = { 'NONE': 0, 'LOW': 0.22, 'HIGH': 0.56 };
    return values[a] || 0;
  }

  // Encoding methods
  static _encodeAV(av) {
    return av === 0.85 ? 'N' : av === 0.62 ? 'A' : av === 0.55 ? 'L' : 'P';
  }

  static _encodeAU(au) {
    return au === 0.77 ? 'L' : 'H';
  }

  static _encodePR(pr) {
    return pr === 0.85 ? 'N' : pr === 0.62 ? 'L' : 'H';
  }

  static _encodeUI(ui) {
    return ui === 0.85 ? 'N' : 'R';
  }

  static _encodeC(c) {
    return c === 0 ? 'N' : c === 0.22 ? 'L' : 'H';
  }

  static _encodeI(i) {
    return i === 0 ? 'N' : i === 0.22 ? 'L' : 'H';
  }

  static _encodeA(a) {
    return a === 0 ? 'N' : a === 0.22 ? 'L' : 'H';
  }

  /**
   * Batch calculate severity
   */
  static calculateBatchSeverity(vulnerabilities) {
    return vulnerabilities.map(vuln => ({
      ...vuln,
      severity: this.calculateSimpleSeverity(vuln)
    }));
  }

  /**
   * Get severity distribution
   */
  static getSeverityDistribution(vulnerabilities) {
    const distribution = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };

    vulnerabilities.forEach(vuln => {
      const severity = this._getSeverityRating(vuln.severity?.score || 50);
      distribution[severity]++;
    });

    return distribution;
  }
}

module.exports = SeverityCalculator;
