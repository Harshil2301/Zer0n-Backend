const crypto = require('crypto');

/**
 * ZkpService handles Cryptographic Commitments (Hash-based Zero-Knowledge Disclosures).
 * 
 * Instead of revealing the raw payload in public/academic reports (which violates ethics),
 * we generate a cryptographically secure random salt and publish:
 *   commitment = SHA256(payload + salt)
 * 
 * This proves knowledge of the payload without revealing it until the bounty is paid.
 */
class ZkpService {
  /**
   * Generates a commitment for a given payload.
   * @param {string} payload - The raw vulnerability payload
   * @returns {Object} - The salt and the commitment hash
   */
  static generateCommitment(payload) {
    if (!payload) return { salt: null, commitment: null };

    // Generate a 32-byte secure random salt
    const salt = crypto.randomBytes(32).toString('hex');
    
    // Create SHA-256 hash commitment
    const hash = crypto.createHash('sha256');
    hash.update(payload + salt);
    const commitment = hash.digest('hex');

    return {
      salt,
      commitment,
      algorithm: 'SHA-256',
      type: 'NIZK-Commitment' // Non-Interactive Zero-Knowledge Commitment
    };
  }

  /**
   * Verifies a commitment against a payload and salt.
   */
  static verifyCommitment(payload, salt, commitment) {
    if (!payload || !salt || !commitment) return false;

    const hash = crypto.createHash('sha256');
    hash.update(payload + salt);
    const expectedCommitment = hash.digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(commitment),
      Buffer.from(expectedCommitment)
    );
  }
}

module.exports = ZkpService;
