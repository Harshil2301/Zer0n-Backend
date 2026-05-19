// Phase 4: Deduplication Engine - Detect similar vulnerabilities
class DeduplicationEngine {
  /**
   * Deduplicate vulnerabilities
   */
  static deduplicateVulnerabilities(vulnerabilities) {
    const deduplicated = [];
    const seen = new Map();

    vulnerabilities.forEach(vuln => {
      const key = this._generateVulnerabilityKey(vuln);
      
      if (!seen.has(key)) {
        seen.set(key, vuln);
        deduplicated.push(vuln);
      } else {
        // Update existing vuln with new occurrence
        const existing = seen.get(key);
        existing.occurrences = (existing.occurrences || 1) + 1;
        existing.endpoints = existing.endpoints || [];
        if (!existing.endpoints.includes(vuln.endpoint)) {
          existing.endpoints.push(vuln.endpoint);
        }
      }
    });

    return deduplicated;
  }

  /**
   * Generate unique vulnerability key
   */
  static _generateVulnerabilityKey(vuln) {
    return `${vuln.type}:${vuln.parameter}`;
  }

  /**
   * Find similar vulnerabilities
   */
  static findSimilar(targetVuln, vulnerabilities, threshold = 0.8) {
    const similar = [];
    const targetVector = this._createVector(targetVuln);

    vulnerabilities.forEach(vuln => {
      if (vuln === targetVuln) return;

      const vulnVector = this._createVector(vuln);
      const similarity = this._calculateSimilarity(targetVector, vulnVector);

      if (similarity >= threshold) {
        similar.push({
          vulnerability: vuln,
          similarity
        });
      }
    });

    return similar.sort((a, b) => b.similarity - a.similarity);
  }

  /**
   * Create vector for similarity calculation
   */
  static _createVector(vuln) {
    return {
      type: vuln.type,
      paramClass: vuln.parameter?.classification || '',
      severity: vuln.severity?.severity || '',
      endpoint: vuln.endpoint
    };
  }

  /**
   * Calculate similarity between vectors
   */
  static _calculateSimilarity(vec1, vec2) {
    let matches = 0;
    let total = 4;

    if (vec1.type === vec2.type) matches++;
    if (vec1.paramClass === vec2.paramClass) matches++;
    if (vec1.severity === vec2.severity) matches++;
    if (vec1.endpoint === vec2.endpoint) matches += 2;

    return matches / total;
  }

  /**
   * Merge duplicate findings
   */
  static mergeDuplicates(vulnerabilities) {
    const merged = [];
    const processed = new Set();

    vulnerabilities.forEach((vuln, index) => {
      if (processed.has(index)) return;

      const key = this._generateVulnerabilityKey(vuln);
      const duplicates = [vuln];

      vulnerabilities.forEach((other, otherIndex) => {
        if (otherIndex <= index) return;
        if (this._generateVulnerabilityKey(other) === key) {
          duplicates.push(other);
          processed.add(otherIndex);
        }
      });

      merged.push({
        ...vuln,
        duplicateCount: duplicates.length - 1,
        allInstances: duplicates
      });

      processed.add(index);
    });

    return merged;
  }

  /**
   * Group vulnerabilities by root cause
   */
  static groupByRootCause(vulnerabilities) {
    const groups = {};

    vulnerabilities.forEach(vuln => {
      const rootCause = this._identifyRootCause(vuln);
      
      if (!groups[rootCause]) {
        groups[rootCause] = [];
      }
      groups[rootCause].push(vuln);
    });

    return groups;
  }

  /**
   * Identify root cause
   */
  static _identifyRootCause(vuln) {
    const { type, parameter } = vuln;
    const paramClass = parameter?.classification || '';

    // Root cause patterns
    if (type === 'SQLi' && (paramClass === 'search' || paramClass === 'filter')) {
      return 'Unsafe database query in search/filter';
    }
    if (type === 'XSS' && paramClass === 'search') {
      return 'Unescaped user input in search results';
    }
    if (type === 'PathTraversal') {
      return 'Insufficient path validation';
    }
    if (type === 'RCE') {
      return 'Unsafe command execution';
    }
    if (type === 'SSRF') {
      return 'Missing URL validation';
    }

    return type;
  }

  /**
   * Generate deduplication report
   */
  static generateDeduplicationReport(originalVulns, deduplicatedVulns) {
    const report = {
      original_count: originalVulns.length,
      deduplicated_count: deduplicatedVulns.length,
      duplicates_removed: originalVulns.length - deduplicatedVulns.length,
      reduction_percentage: Math.round(
        ((originalVulns.length - deduplicatedVulns.length) / originalVulns.length) * 100
      ),
      by_type: {}
    };

    deduplicatedVulns.forEach(vuln => {
      const type = vuln.type;
      if (!report.by_type[type]) {
        report.by_type[type] = { original: 0, deduplicated: 0 };
      }
      report.by_type[type].deduplicated++;
    });

    originalVulns.forEach(vuln => {
      const type = vuln.type;
      if (report.by_type[type]) {
        report.by_type[type].original++;
      }
    });

    return report;
  }
}

module.exports = DeduplicationEngine;
