// Phase 0: Target Scoring - SimHash for deduplication, fingerprinting for ranking
const simhash = require('simhash-js');

class TargetScorer {
  /**
   * Generate SimHash for deduplication
   */
  static generateSimHash(content) {
    try {
      const hash = simhash(content);
      return hash;
    } catch (error) {
      console.error('Error generating SimHash:', error);
      return null;
    }
  }

  /**
   * Calculate similarity between two SimHashes (0-1 scale)
   */
  static calculateSimilarity(hash1, hash2) {
    if (!hash1 || !hash2) return 0;
    
    const bits1 = BigInt(hash1).toString(2).padStart(64, '0');
    const bits2 = BigInt(hash2).toString(2).padStart(64, '0');
    
    let hammingDistance = 0;
    for (let i = 0; i < bits1.length; i++) {
      if (bits1[i] !== bits2[i]) hammingDistance++;
    }
    
    return 1 - (hammingDistance / 64);
  }

  /**
   * Calculate asset priority score (0-100)
   */
  static calculatePriorityScore(asset, metadata = {}) {
    let score = 0;

    // Technology stack scoring
    if (metadata.technologies) {
      const vulnTechs = this._getVulnerableTechs();
      const matchingTechs = metadata.technologies.filter(tech => 
        vulnTechs.includes(tech.toLowerCase())
      );
      score += matchingTechs.length * 15;
    }

    // Endpoint count
    if (metadata.endpointCount) {
      score += Math.min(metadata.endpointCount / 10, 20); // Max 20 points
    }

    // Parameter count
    if (metadata.parameterCount) {
      score += Math.min(metadata.parameterCount / 20, 15); // Max 15 points
    }

    // Previous vulnerability history
    if (metadata.previousVulnCount) {
      score += Math.min(metadata.previousVulnCount * 5, 20); // Max 20 points
    }

    // Authentication complexity
    if (metadata.hasAuthentication) {
      score += 10;
    }

    // API endpoints
    if (metadata.hasAPI) {
      score += 10;
    }

    // File upload functionality
    if (metadata.hasFileUpload) {
      score += 8;
    }

    // Database interaction
    if (metadata.hasDatabaseInteraction) {
      score += 7;
    }

    return Math.min(score, 100);
  }

  /**
   * Calculate vulnerability severity (CVSS-like scoring)
   */
  static calculateSeverity(vulnerability) {
    const { type, impact, auth, complexity, scope } = vulnerability;

    let score = 0;

    // Base score by vulnerability type
    const typeScores = {
      'RCE': 40,
      'SQLi': 35,
      'XSS': 25,
      'SSRF': 30,
      'XXE': 30,
      'PathTraversal': 28,
      'AuthBypass': 40,
      'CSRF': 20,
      'LFI': 28,
      'PrivilegeEscalation': 35,
      'InfoDisclosure': 15,
      'DoS': 20,
      'BrokenAuth': 35
    };

    score = typeScores[type] || 15;

    // Impact modifier
    if (impact === 'high') score += 25;
    else if (impact === 'medium') score += 15;
    else if (impact === 'low') score += 5;

    // Authentication required
    if (auth === 'none') score += 20;
    else if (auth === 'low') score += 10;

    // Complexity modifier
    if (complexity === 'low') score += 15;
    else if (complexity === 'high') score -= 10;

    // Scope changed
    if (scope === 'changed') score += 10;

    score = Math.min(score, 100);

    if (score >= 90) return 'CRITICAL';
    if (score >= 70) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'INFO';
  }

  /**
   * Get vulnerable technologies list
   */
  static _getVulnerableTechs() {
    return [
      'wordpress',
      'joomla',
      'drupal',
      'php',
      'nodejs',
      'express',
      'apache',
      'nginx',
      'mysql',
      'postgresql',
      'mongodb',
      'jquery',
      'bootstrap',
      'angular',
      'react',
      'vue',
      'asp.net',
      'java',
      'python',
      'django',
      'flask',
      'rails',
      'ruby'
    ];
  }

  /**
   * Rank assets by priority
   */
  static rankAssets(assets) {
    return assets.sort((a, b) => (b.score || 0) - (a.score || 0));
  }

  /**
   * Detect duplicate assets using SimHash
   */
  static findDuplicates(assets, threshold = 0.85) {
    const duplicates = [];

    for (let i = 0; i < assets.length; i++) {
      for (let j = i + 1; j < assets.length; j++) {
        const similarity = this.calculateSimilarity(
          assets[i].simhash,
          assets[j].simhash
        );

        if (similarity >= threshold) {
          duplicates.push({
            asset1: assets[i].assetId,
            asset2: assets[j].assetId,
            similarity
          });
        }
      }
    }

    return duplicates;
  }
}

module.exports = TargetScorer;
