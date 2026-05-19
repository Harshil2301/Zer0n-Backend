// Phase 0: Scope Service - Parse and manage target scopes
const { db } = require('../../config/firebase');
const { v4: uuidv4 } = require('uuid');

class ScopeService {
  /**
   * Parse scope input (domains, IPs, CIDR ranges, subdomains)
   */
  static async parseScope(scopeInput) {
    const scopes = {
      domains: [],
      ips: [],
      ipRanges: [],
      subdomains: [],
      disallowedScans: [],
      allowedMethods: []
    };

    if (!scopeInput) return scopes;

    const lines = scopeInput.split('\n').map(line => line.trim()).filter(line => line);

    for (const line of lines) {
      if (line.startsWith('-')) {
        // Disallowed scope
        scopes.disallowedScans.push(line.replace('-', '').trim());
      } else if (this._isCIDR(line)) {
        scopes.ipRanges.push(line);
      } else if (this._isIP(line)) {
        scopes.ips.push(line);
      } else if (this._isDomain(line)) {
        scopes.domains.push(line);
        // Extract subdomains if present
        if (line.includes('*.')) {
          scopes.subdomains.push(line);
        }
      }
    }

    return scopes;
  }

  /**
   * Save scope rules to Firestore
   */
  static async saveScope(programId, scopeData) {
    try {
      await db.collection('programs').doc(programId).set({
        rules: scopeData,
        createdAt: new Date(),
        updatedAt: new Date(),
        status: 'active'
      }, { merge: true });

      return {
        success: true,
        message: 'Scope rules saved successfully',
        programId
      };
    } catch (error) {
      console.error('Error saving scope:', error);
      throw error;
    }
  }

  /**
   * Get scope rules for a program
   */
  static async getScope(programId) {
    try {
      const doc = await db.collection('programs').doc(programId).get();
      if (!doc.exists) {
        return null;
      }
      return doc.data().rules;
    } catch (error) {
      console.error('Error getting scope:', error);
      throw error;
    }
  }

  /**
   * Validate if target is within scope
   */
  static isInScope(target, scopeRules) {
    // Check if target is in disallowed list
    if (scopeRules.disallowedScans.includes(target)) {
      return false;
    }

    // Check if target matches allowed domains
    for (const domain of scopeRules.domains) {
      if (domain.includes('*')) {
        const regex = this._wildcardToRegex(domain);
        if (regex.test(target)) return true;
      } else if (target === domain || target.endsWith('.' + domain)) {
        return true;
      }
    }

    // Check IPs
    if (scopeRules.ips.includes(target)) {
      return true;
    }

    return false;
  }

  /**
   * Helper: Check if string is valid domain
   */
  static _isDomain(str) {
    const domainRegex = /^([\w-]+\.)*[\w-]+\.[a-z]{2,}(\.\*)?$/i;
    return domainRegex.test(str);
  }

  /**
   * Helper: Check if string is valid IP
   */
  static _isIP(str) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipRegex.test(str);
  }

  /**
   * Helper: Check if string is CIDR notation
   */
  static _isCIDR(str) {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    return cidrRegex.test(str);
  }

  /**
   * Helper: Convert wildcard pattern to regex
   */
  static _wildcardToRegex(pattern) {
    const regexPattern = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*');
    return new RegExp(`^${regexPattern}$`);
  }
}

module.exports = ScopeService;
