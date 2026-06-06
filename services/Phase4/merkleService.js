const crypto = require('crypto');

class MerkleService {
  /**
   * Generates a SHA-256 hash
   */
  static hash(data) {
    return crypto.createHash('sha256').update(typeof data === 'string' ? data : JSON.stringify(data)).digest('hex');
  }

  /**
   * Generates a Merkle Root and proof for a batch of vulnerabilities
   * 
   * This provides cryptographic proof of the state of the scan findings,
   * without exposing the sensitive payloads on-chain immediately.
   */
  static generateTree(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      return { root: null, leaves: [] };
    }

    // Step 1: Hash all individual vulnerabilities to create leaves
    const leaves = vulnerabilities.map(vuln => {
      const sanitizedVuln = {
        id: vuln.id || 'unknown',
        type: vuln.type || 'unknown',
        severity: vuln.severity || 'unknown',
        endpoint: vuln.endpoint?.url || 'unknown',
        parameter: vuln.parameter?.name || 'unknown'
      };
      return this.hash(sanitizedVuln);
    });

    // Step 2: Build the tree upwards
    let currentLevel = [...leaves];
    
    while (currentLevel.length > 1) {
      const nextLevel = [];
      
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        // If odd number of nodes, duplicate the last one
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        
        // Hash the concatenated pair
        nextLevel.push(this.hash(left + right));
      }
      
      currentLevel = nextLevel;
    }

    return {
      root: currentLevel[0],
      leaves: leaves
    };
  }
}

module.exports = MerkleService;
