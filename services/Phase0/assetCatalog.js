// Phase 0: Asset Catalog - Database operations for asset management
const { db } = require('../../config/firebase');
const { v4: uuidv4 } = require('uuid');

class AssetCatalog {
  /**
   * Create or update asset in catalog
   */
  static async addAsset(programId, assetData) {
    try {
      const assetId = uuidv4();
      const asset = {
        assetId,
        programId,
        ...assetData,
        metadata: assetData.metadata || {},
        score: assetData.score || 0,
        status: 'queued', // queued, scanning, complete
        recon_data: {},
        parameters: [],
        vulnerabilities: [],
        last_scanned: null,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      await db.collection('assets').doc(assetId).set(asset);
      return asset;
    } catch (error) {
      console.error('Error adding asset:', error);
      throw error;
    }
  }

  /**
   * Get asset by ID
   */
  static async getAsset(assetId) {
    try {
      const doc = await db.collection('assets').doc(assetId).get();
      if (!doc.exists) {
        return null;
      }
      return doc.data();
    } catch (error) {
      console.error('Error getting asset:', error);
      throw error;
    }
  }

  /**
   * Get all assets for a program
   */
  static async getAssetsByProgram(programId) {
    try {
      const snapshot = await db.collection('assets')
        .where('programId', '==', programId)
        .get();
      
      const assets = [];
      snapshot.forEach(doc => {
        assets.push(doc.data());
      });
      return assets;
    } catch (error) {
      console.error('Error getting assets by program:', error);
      throw error;
    }
  }

  /**
   * Update asset status
   */
  static async updateAssetStatus(assetId, status) {
    try {
      await db.collection('assets').doc(assetId).update({
        status,
        updatedAt: new Date()
      });
      return { success: true };
    } catch (error) {
      console.error('Error updating asset status:', error);
      throw error;
    }
  }

  /**
   * Add recon data to asset
   */
  static async addReconData(assetId, reconData) {
    try {
      await db.collection('assets').doc(assetId).update({
        recon_data: reconData,
        updatedAt: new Date()
      });
      return { success: true };
    } catch (error) {
      console.error('Error adding recon data:', error);
      throw error;
    }
  }

  /**
   * Add parameters to asset
   */
  static async addParameters(assetId, parameters) {
    try {
      const asset = await this.getAsset(assetId);
      const existingParams = asset.parameters || [];
      const merged = Array.from(new Set([...existingParams, ...parameters]));

      await db.collection('assets').doc(assetId).update({
        parameters: merged,
        updatedAt: new Date()
      });
      return { success: true, count: merged.length };
    } catch (error) {
      console.error('Error adding parameters:', error);
      throw error;
    }
  }

  /**
   * Add vulnerability to asset
   */
  static async addVulnerability(assetId, vulnerability) {
    try {
      const vulnId = uuidv4();
      const vuln = {
        vulnId,
        assetId,
        ...vulnerability,
        createdAt: new Date()
      };

      await db.collection('vulnerabilities').doc(vulnId).set(vuln);
      
      // Also add to asset's vulnerabilities array
      const asset = await this.getAsset(assetId);
      const vulns = asset.vulnerabilities || [];
      vulns.push(vulnId);

      await db.collection('assets').doc(assetId).update({
        vulnerabilities: vulns,
        updatedAt: new Date()
      });

      return vuln;
    } catch (error) {
      console.error('Error adding vulnerability:', error);
      throw error;
    }
  }

  /**
   * Get vulnerabilities for asset
   */
  static async getVulnerabilities(assetId) {
    try {
      const snapshot = await db.collection('vulnerabilities')
        .where('assetId', '==', assetId)
        .get();
      
      const vulns = [];
      snapshot.forEach(doc => {
        vulns.push(doc.data());
      });
      return vulns;
    } catch (error) {
      console.error('Error getting vulnerabilities:', error);
      throw error;
    }
  }

  /**
   * Update asset score
   */
  static async updateAssetScore(assetId, score) {
    try {
      await db.collection('assets').doc(assetId).update({
        score,
        updatedAt: new Date()
      });
      return { success: true };
    } catch (error) {
      console.error('Error updating asset score:', error);
      throw error;
    }
  }

  /**
   * Get next asset to scan
   */
  static async getNextAssetToScan(programId) {
    try {
      const snapshot = await db.collection('assets')
        .where('programId', '==', programId)
        .where('status', '==', 'queued')
        .orderBy('score', 'desc')
        .limit(1)
        .get();

      if (snapshot.empty) {
        return null;
      }

      return snapshot.docs[0].data();
    } catch (error) {
      console.error('Error getting next asset:', error);
      throw error;
    }
  }

  /**
   * Delete asset
   */
  static async deleteAsset(assetId) {
    try {
      await db.collection('assets').doc(assetId).delete();
      return { success: true };
    } catch (error) {
      console.error('Error deleting asset:', error);
      throw error;
    }
  }
}

module.exports = AssetCatalog;
