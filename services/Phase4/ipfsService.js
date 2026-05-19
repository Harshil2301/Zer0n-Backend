const axios = require('axios');

class IpfsService {
  /**
   * Uploads a vulnerability report to IPFS (Pinata).
   * @param {Object} reportData - The JSON report of vulnerabilities
   * @returns {Promise<string>} The IPFS CID hash
   */
  static async uploadToIPFS(reportData) {
    console.log(`\n  ☁️  Uploading Proof of Concept to IPFS via Pinata...`);
    
    const jwt = process.env.PINATA_JWT;
    
    if (!jwt || jwt === 'eyJhbG... (paste your Pinata JWT here)') {
      console.error("  ❌ Missing PINATA_JWT in .env");
      throw new Error("Missing Pinata JWT");
    }

    try {
      const data = JSON.stringify({
        pinataContent: reportData,
        pinataMetadata: {
          name: `ZerOn_Report_${Date.now()}.json`
        }
      });

      const config = {
        method: 'post',
        url: 'https://api.pinata.cloud/pinning/pinJSONToIPFS',
        headers: { 
          'Content-Type': 'application/json', 
          'Authorization': `Bearer ${jwt}`
        },
        data: data
      };

      const res = await axios(config);
      const cid = res.data.IpfsHash;
      
      console.log(`  ✅ IPFS Upload Complete. CID: ${cid}`);
      return cid;
    } catch (error) {
      console.error(`  ❌ Failed to upload to Pinata:`, error.response ? error.response.data : error.message);
      throw error;
    }
  }
}

module.exports = IpfsService;
