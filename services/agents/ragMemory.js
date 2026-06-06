const { db } = require('../../config/firebase');

/**
 * RAG Memory Store
 * Allows the Mixture of Agents to learn from past false positives and mistakes.
 * This is a Global Memory - it learns from all scans across all users.
 */
class RagMemory {
  /**
   * Log a new lesson when the Reflection Loop rejects a finding
   */
  static async logFalsePositive(vulnerabilityType, payload, rejectionReason) {
    if (!db) {
      console.warn('[RAG] Firebase not initialized, skipping memory log');
      return false;
    }
    
    try {
      const ragRef = db.collection('ragMemory');
      await ragRef.add({
        type: vulnerabilityType,
        payloadPattern: payload,
        reason: rejectionReason,
        timestamp: new Date().toISOString()
      });
      return true;
    } catch (e) {
      console.error('[RAG] Failed to log memory:', e);
      return false;
    }
  }

  /**
   * Fetch context for an agent to prevent repeating past mistakes
   */
  static async getContextForAgent(vulnerabilityType) {
    if (!db) return "";
    
    try {
      const ragRef = db.collection('ragMemory');
      // Simple query: where type == vulnerabilityType, order by timestamp desc, limit 5
      const snapshot = await ragRef
        .where('type', '==', vulnerabilityType)
        .orderBy('timestamp', 'desc')
        .limit(5)
        .get();

      if (snapshot.empty) return "";

      const relevantLessons = [];
      snapshot.forEach(doc => {
        relevantLessons.push(doc.data());
      });

      let contextStr = "\n\nCRITICAL CONTEXT FROM PREVIOUS SCANS (RAG MEMORY):\n";
      contextStr += "The following patterns have historically been flagged as FALSE POSITIVES on this system. DO NOT report them again unless you have new absolute proof:\n";
      
      relevantLessons.forEach((lesson, i) => {
        contextStr += `${i + 1}. Payload/Pattern: "${lesson.payloadPattern}" -> Reason it was rejected: "${lesson.reason}"\n`;
      });

      return contextStr;
    } catch (e) {
      console.error('[RAG] Failed to read memory:', e);
      return "";
    }
  }
}

module.exports = RagMemory;
