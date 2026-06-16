const { db } = require('../../config/firebase');

/**
 * RAG Memory Store — Universal Intelligence Engine
 *
 * This is GLOBAL memory, shared across ALL users and ALL scans.
 * It learns from three categories of events:
 *
 *   1. FALSE POSITIVES  — Payloads/patterns the Reflection Loop rejected.
 *      Prevents agents from wasting time on things we know don't work.
 *
 *   2. TRUE POSITIVES   — Confirmed vulnerabilities with their proof & remediation.
 *      Helps agents know what real exploitation looks like on similar stacks.
 *
 *   3. DOMAIN INTEL     — Tech stack fingerprints, WAF behaviour, anomalous responses.
 *      Lets agents tailor payloads to the target before even firing.
 *
 * Memory entries have NO userId — they belong to the engine, not to any account.
 */

// ─── In-process L1 cache to avoid repeated Firestore reads ─────────────────
// Cache per vulnerability type, invalidated after 10 minutes.
const _cache = {}; // { [type]: { ts: number, context: string } }
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

class RagMemory {

  // ── 1. Log a False Positive ────────────────────────────────────────────────
  static async logFalsePositive(vulnerabilityType, payload, rejectionReason) {
    if (!db) return false;
    try {
      await db.collection('ragMemory').add({
        category: 'false_positive',
        type: vulnerabilityType,
        payloadPattern: payload,
        reason: rejectionReason,
        seenCount: 1,          // incremented on duplicates
        timestamp: new Date().toISOString()
      });
      _cache[vulnerabilityType] = null; // Invalidate cache for this type
      return true;
    } catch (e) {
      console.error('[RAG] Failed to log false positive:', e.message);
      return false;
    }
  }

  // ── 2. Log a Confirmed True Positive ──────────────────────────────────────
  // Called by masterAgent after a finding passes all reflection stages.
  static async logTruePositive(finding, domain) {
    if (!db) return false;
    try {
      await db.collection('ragMemory').add({
        category: 'true_positive',
        type: finding.type,
        domain: domain || 'unknown',
        endpoint: finding.endpoint || '',
        parameter: finding.parameter || '',
        severity: finding.severity || 'Medium',
        cvss: finding.cvss || null,
        cwe: finding.cwe || null,
        proof: (finding.proof || '').substring(0, 500), // cap to avoid bloat
        remediation: finding.remediation || '',
        payload: finding.payload || '',
        timestamp: new Date().toISOString()
      });
      _cache[finding.type] = null; // Invalidate cache
      return true;
    } catch (e) {
      console.error('[RAG] Failed to log true positive:', e.message);
      return false;
    }
  }

  // ── 3. Log Domain Intelligence ─────────────────────────────────────────────
  // Called after fingerprinting: tech stack, WAF presence, server behaviour.
  static async logDomainIntel(domain, techStack = [], wafDetected = false, notes = '') {
    if (!db) return false;
    try {
      // Upsert: store one intel doc per domain (overwrite old one)
      await db.collection('ragMemory').doc(`domain_${domain.replace(/[^a-zA-Z0-9]/g, '_')}`).set({
        category: 'domain_intel',
        type: 'DomainIntel',
        domain,
        techStack,
        wafDetected,
        notes,
        timestamp: new Date().toISOString()
      }, { merge: true });
      return true;
    } catch (e) {
      console.error('[RAG] Failed to log domain intel:', e.message);
      return false;
    }
  }

  // ── 4. Get Context for an Agent ────────────────────────────────────────────
  // Returns a formatted string injected into the agent's LLM prompt.
  // Pulls false positives + true positives for this vuln type + domain intel.
  static async getContextForAgent(vulnerabilityType, domain = null) {
    if (!db) return '';

    // L1 cache hit
    const cacheKey = `${vulnerabilityType}_${domain || 'any'}`;
    if (_cache[cacheKey] && (Date.now() - _cache[cacheKey].ts) < CACHE_TTL_MS) {
      return _cache[cacheKey].context;
    }

    try {
      const ragRef = db.collection('ragMemory');
      const snapshot = await ragRef
        .where('type', '==', vulnerabilityType)
        .limit(150)
        .get();

      const docs = [];
      snapshot.forEach(d => docs.push(d.data()));

      // Sort newest first
      docs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      const falsePositives = docs.filter(d => d.category === 'false_positive').slice(0, 8);
      const truePositives  = docs.filter(d => d.category === 'true_positive').slice(0, 5);

      let ctx = '';

      if (falsePositives.length > 0) {
        ctx += '\n\n━━ RAG MEMORY: KNOWN FALSE POSITIVES ━━\n';
        ctx += 'The following have been REJECTED in past scans. Skip them unless you have new evidence:\n';
        falsePositives.forEach((fp, i) => {
          ctx += `  ${i + 1}. Pattern: "${fp.payloadPattern}" → Rejected because: "${fp.reason}"\n`;
        });
      }

      if (truePositives.length > 0) {
        ctx += '\n━━ RAG MEMORY: CONFIRMED VULNERABILITIES FROM PAST SCANS ━━\n';
        ctx += 'These are real vulnerabilities found before. Use them as reference for what a true positive looks like:\n';
        truePositives.forEach((tp, i) => {
          ctx += `  ${i + 1}. ${tp.type} on ${tp.domain} [param: ${tp.parameter}] — Severity: ${tp.severity}`;
          if (tp.cwe) ctx += ` | CWE: ${tp.cwe}`;
          ctx += '\n';
          if (tp.remediation) ctx += `     Fix: ${tp.remediation.substring(0, 150)}\n`;
        });
      }

      // Domain-specific intel if requested
      if (domain) {
        try {
          const intelDoc = await ragRef.doc(`domain_${domain.replace(/[^a-zA-Z0-9]/g, '_')}`).get();
          if (intelDoc.exists) {
            const intel = intelDoc.data();
            ctx += '\n━━ RAG MEMORY: DOMAIN INTEL ━━\n';
            if (intel.techStack?.length) ctx += `  Tech Stack: ${intel.techStack.join(', ')}\n`;
            if (intel.wafDetected) ctx += `  ⚠ WAF detected — use encoding/evasion techniques\n`;
            if (intel.notes) ctx += `  Notes: ${intel.notes}\n`;
          }
        } catch (_) { /* non-fatal */ }
      }

      // Write to L1 cache
      _cache[cacheKey] = { ts: Date.now(), context: ctx };
      return ctx;
    } catch (e) {
      console.error('[RAG] Failed to read context:', e.message);
      return '';
    }
  }

  // ── 5. Get Stats (for admin/dashboard) ────────────────────────────────────
  static async getStats() {
    if (!db) return {};
    try {
      const snapshot = await db.collection('ragMemory').get();
      const counts = { false_positive: 0, true_positive: 0, domain_intel: 0, total: 0 };
      const byType = {};
      snapshot.forEach(d => {
        const data = d.data();
        counts.total++;
        if (data.category) counts[data.category] = (counts[data.category] || 0) + 1;
        if (data.type) byType[data.type] = (byType[data.type] || 0) + 1;
      });
      return { counts, byType };
    } catch (e) {
      return {};
    }
  }
}

module.exports = RagMemory;
