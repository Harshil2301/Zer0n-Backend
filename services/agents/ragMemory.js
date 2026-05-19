const fs = require('fs');
const path = require('path');

const MEMORY_FILE = path.join(__dirname, '..', '..', 'config', 'rag-memory.json');

/**
 * RAG Memory Store
 * Allows the Mixture of Agents to learn from past false positives and mistakes.
 * This is a Global Memory - it learns from all scans across all users.
 */
class RagMemory {
  static initialize() {
    const configDir = path.dirname(MEMORY_FILE);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    if (!fs.existsSync(MEMORY_FILE)) {
      fs.writeFileSync(MEMORY_FILE, JSON.stringify({ learnedLessons: [] }, null, 2));
    }
  }

  /**
   * Log a new lesson when the Reflection Loop rejects a finding
   */
  static logFalsePositive(vulnerabilityType, payload, rejectionReason) {
    this.initialize();
    try {
      const data = JSON.parse(fs.readFileSync(MEMORY_FILE, 'utf8'));
      
      const newLesson = {
        type: vulnerabilityType,
        payloadPattern: payload,
        reason: rejectionReason,
        timestamp: new Date().toISOString()
      };

      data.learnedLessons.push(newLesson);
      fs.writeFileSync(MEMORY_FILE, JSON.stringify(data, null, 2));
      
      return true;
    } catch (e) {
      console.error('[RAG] Failed to log memory:', e);
      return false;
    }
  }

  /**
   * Fetch context for an agent to prevent repeating past mistakes
   */
  static getContextForAgent(vulnerabilityType) {
    this.initialize();
    try {
      const data = JSON.parse(fs.readFileSync(MEMORY_FILE, 'utf8'));
      
      // Filter lessons relevant to this agent
      const relevantLessons = data.learnedLessons
        .filter(l => l.type === vulnerabilityType)
        .slice(-5); // Only take the 5 most recent to save token context

      if (relevantLessons.length === 0) return "";

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
