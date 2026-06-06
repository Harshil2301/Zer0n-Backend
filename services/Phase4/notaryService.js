const crypto = require('crypto');
require('dotenv').config();

/**
 * NotaryService acts as an independent cryptographic node
 * that signs scan results and Merkle Roots to prevent tampering.
 * 
 * In a fully decentralized architecture, this service would run on 
 * independent infrastructure (e.g. academic or validator nodes) 
 * to provide a trustless verification layer.
 */
class NotaryService {
  constructor() {
    this.secret = process.env.NOTARY_SECRET;
    if (!this.secret) {
      console.warn('[NotaryService] NOTARY_SECRET missing from environment. Signatures will fail.');
    }
    this.nodeId = 'NOTARY_NODE_' + crypto.createHash('md5').update(this.secret || 'default').digest('hex').substring(0, 8).toUpperCase();
  }

  /**
   * Signs a payload (e.g., Merkle Root) with the Notary's secret key
   * to attest to the scan's authenticity at a specific point in time.
   */
  signPayload(payload) {
    if (!payload || !this.secret) return null;
    
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    
    const hmac = crypto.createHmac('sha256', this.secret);
    hmac.update(data);
    const signature = hmac.digest('hex');
    
    return {
      nodeId: this.nodeId,
      signature: signature,
      timestamp: new Date().toISOString(),
      algorithm: 'HMAC-SHA256'
    };
  }

  /**
   * Verifies a signature using the Notary's secret key
   */
  verifySignature(payload, signature) {
    if (!payload || !signature || !this.secret) return false;
    
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    
    const hmac = crypto.createHmac('sha256', this.secret);
    hmac.update(data);
    const expectedSignature = hmac.digest('hex');
    
    // Timing-safe equal prevents timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }
}

// Export as a singleton
module.exports = new NotaryService();
