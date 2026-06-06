/**
 * ZerOn PDF Report Generator
 * Uses Puppeteer to convert a beautiful HTML report into a professional PDF
 * 
 * Endpoint: GET /api/scan/:scanId/report.pdf
 */
const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

class PDFReportService {

  /**
   * Generate a PDF report for a completed scan
   * @param {object} scan - The full scan object from Firebase/memory
   * @returns {Buffer} - PDF file as a buffer
   */
  static async generatePDF(scan) {
    const html = this._buildHTML(scan);
    
    // Use environment variable for executable path (required for Render)
    const browser = await puppeteer.launch({
      headless: 'new',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || null,
      args: [
        '--no-sandbox', 
        '--disable-setuid-sandbox', 
        '--disable-dev-shm-usage',
        '--single-process',
        '--no-zygote'
      ]
    });

    try {
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'networkidle0' });
      const pdfBuffer = await page.pdf({
        format: 'A4',
        printBackground: true,
        margin: { top: '20mm', bottom: '20mm', left: '15mm', right: '15mm' }
      });
      return pdfBuffer;
    } finally {
      await browser.close();
    }
  }

  static _severityColor(severity) {
    const s = (severity || '').toUpperCase();
    if (s === 'CRITICAL') return '#ff2d55';
    if (s === 'HIGH')     return '#ff6b35';
    if (s === 'MEDIUM')   return '#ffd60a';
    if (s === 'LOW')      return '#30d158';
    return '#636366';
  }

  static _severityBg(severity) {
    const s = (severity || '').toUpperCase();
    if (s === 'CRITICAL') return 'rgba(255,45,85,0.12)';
    if (s === 'HIGH')     return 'rgba(255,107,53,0.12)';
    if (s === 'MEDIUM')   return 'rgba(255,214,10,0.12)';
    if (s === 'LOW')      return 'rgba(48,209,88,0.12)';
    return 'rgba(99,99,102,0.12)';
  }

  static _cvssForVuln(vuln) {
    const CVSS = {
      'SQL Injection':             9.8,
      'Auth Bypass':               9.5,
      'Cross-Site Scripting (XSS)': 6.1,
      'Security Misconfiguration': null, // per-header
    };
    if (vuln.type === 'Security Misconfiguration') {
      const h = { 'strict-transport-security': 7.5, 'content-security-policy': 7.5, 'x-frame-options': 6.1, 'x-content-type-options': 4.3, 'x-xss-protection': 4.3 };
      return h[(vuln.parameter || '').toLowerCase()] || 4.3;
    }
    return CVSS[vuln.type] || (vuln.cvss || 5.0);
  }

  static _severityFromCvss(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  }

  static _buildHTML(scan) {
    const vulns = scan.vulnerabilities || [];
    const domain = scan.domain || 'Unknown';
    const scanDate = new Date(scan.createdAt || Date.now()).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    vulns.forEach(v => {
      const cvss = this._cvssForVuln(v);
      const sev = this._severityFromCvss(cvss);
      counts[sev] = (counts[sev] || 0) + 1;
    });

    const riskLevel = counts.CRITICAL > 0 ? 'CRITICAL' : counts.HIGH > 0 ? 'HIGH' : counts.MEDIUM > 0 ? 'MEDIUM' : 'LOW';

    const vulnCards = vulns.map((v, i) => {
      const cvss = this._cvssForVuln(v);
      const sev  = this._severityFromCvss(cvss);
      const color = this._severityColor(sev);
      const bg    = this._severityBg(sev);
      return `
      <div class="vuln-card" style="border-left: 4px solid ${color}; background: ${bg};">
        <div class="vuln-header">
          <div class="vuln-number">#${i + 1}</div>
          <div class="vuln-title">${v.type}</div>
          <div class="cvss-badge" style="background: ${color}; color: #000;">CVSS ${cvss.toFixed(1)}</div>
          <div class="sev-badge" style="color: ${color}; border: 1px solid ${color};">${sev}</div>
        </div>
        <div class="vuln-details">
          <div class="detail-row"><span class="label">Endpoint</span><code>${v.endpoint || 'N/A'}</code></div>
          <div class="detail-row"><span class="label">Parameter</span><code>${v.parameter || 'N/A'}</code></div>
          <div class="detail-row"><span class="label">Payload</span><code>${(v.payload || 'N/A').substring(0, 100)}</code></div>
          <div class="detail-row"><span class="label">Evidence</span><span class="proof">${(v.proof || v.description || 'See server response').substring(0, 200)}</span></div>
        </div>
        <div class="remediation-box">
          <strong>Remediation:</strong>
          ${v.type === 'SQL Injection' ? 'Use parameterized queries (prepared statements). Never concatenate user input into SQL.' :
            v.type === 'Cross-Site Scripting (XSS)' ? 'HTML-encode all user input before rendering. Implement Content-Security-Policy headers.' :
            v.type === 'Security Misconfiguration' ? `Add the missing <code>${v.parameter}</code> header to all HTTP responses.` :
            'Implement proper input validation and output encoding. Follow OWASP guidelines.'}
        </div>
      </div>`;
    }).join('');

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
  body { font-family: 'Segoe UI', -apple-system, sans-serif; background: #0d0d0d !important; color: #e8e8e8; font-size: 13px; -webkit-print-color-adjust: exact !important; }
  
  .cover { background: linear-gradient(135deg, #0d0d0d 0%, #1a0a2e 50%, #0d1a0d 100%) !important; padding: 60px 50px; min-height: 250px; border-bottom: 2px solid #00ff88; }
  .cover-top { display: flex; justify-content: space-between; align-items: flex-start; }
  .brand { font-size: 28px; font-weight: 900; letter-spacing: 4px; color: #00ff88; }
  .brand span { color: #00d4ff; }
  .report-type { font-size: 11px; color: #888; letter-spacing: 3px; text-transform: uppercase; margin-top: 4px; }
  .cover-body { margin-top: 40px; }
  .target-domain { font-size: 36px; font-weight: 700; color: #fff; margin-bottom: 8px; }
  .scan-meta { color: #888; font-size: 13px; }
  .scan-meta span { margin-right: 24px; }

  .risk-banner { display: flex; gap: 16px; margin-top: 24px; }
  .risk-chip { padding: 8px 20px; border-radius: 20px; font-weight: 700; font-size: 12px; letter-spacing: 1px; }
  
  .stats-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; padding: 30px 50px; background: #111; border-bottom: 1px solid #222; }
  .stat-box { text-align: center; padding: 20px; border-radius: 8px; background: #1a1a1a; }
  .stat-number { font-size: 32px; font-weight: 900; }
  .stat-label { font-size: 10px; letter-spacing: 2px; color: #888; text-transform: uppercase; margin-top: 4px; }
  
  .section { padding: 30px 50px; }
  .section-title { font-size: 16px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #00d4ff; margin-bottom: 20px; padding-bottom: 8px; border-bottom: 1px solid #222; }
  
  .exec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .exec-item { background: #1a1a1a; border-radius: 8px; padding: 16px; }
  .exec-item-label { font-size: 10px; letter-spacing: 2px; color: #888; text-transform: uppercase; margin-bottom: 6px; }
  .exec-item-value { font-size: 14px; font-weight: 600; color: #fff; }
  
  .vuln-card { border-radius: 8px; padding: 20px; margin-bottom: 16px; page-break-inside: avoid; }
  .vuln-header { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
  .vuln-number { font-size: 11px; color: #888; font-weight: 700; min-width: 24px; }
  .vuln-title { font-size: 15px; font-weight: 700; color: #fff; flex: 1; }
  .cvss-badge { font-size: 11px; font-weight: 800; padding: 4px 10px; border-radius: 12px; letter-spacing: 1px; }
  .sev-badge { font-size: 10px; font-weight: 700; padding: 3px 10px; border-radius: 10px; letter-spacing: 1px; }
  .vuln-details { display: grid; gap: 8px; margin-bottom: 14px; }
  .detail-row { display: flex; gap: 12px; align-items: flex-start; }
  .label { font-size: 10px; letter-spacing: 1px; color: #888; text-transform: uppercase; min-width: 70px; padding-top: 2px; }
  code { background: rgba(0,0,0,0.4); padding: 2px 8px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; color: #00d4ff; word-break: break-all; }
  .proof { font-size: 12px; color: #ccc; word-break: break-all; }
  .remediation-box { background: rgba(0,0,0,0.3); border-radius: 6px; padding: 12px 14px; font-size: 12px; color: #bbb; border-left: 3px solid #00ff88; }
  .remediation-box strong { color: #00ff88; }

  .footer { padding: 20px 50px; border-top: 1px solid #222; display: flex; justify-content: space-between; color: #555; font-size: 11px; }
  
  @media print {
    table { page-break-inside: avoid; }
    tr { page-break-inside: avoid; page-break-after: auto; }
    h2, h3 { page-break-after: avoid; }
    .vuln-card { page-break-inside: avoid; margin-bottom: 20px; }
  }

  @page { margin: 0; }
</style>
</head>
<body>

<div class="cover">
  <div class="cover-top">
    <div>
      <div class="brand">ZER<span>ON</span></div>
      <div class="report-type">Vulnerability Assessment Report</div>
    </div>
    <div style="text-align:right; color:#555; font-size:11px;">
      <div>CONFIDENTIAL</div>
      <div>Scan ID: ${scan.scanId?.substring(0, 16) || 'N/A'}</div>
    </div>
  </div>
  <div class="cover-body">
    <div class="target-domain">${domain}</div>
    <div class="scan-meta">
      <span>📅 ${scanDate}</span>
      <span>🔬 AI-Powered VAPT</span>
      <span>⚡ Mixture of Agents</span>
    </div>
    <div class="risk-banner">
      <div class="risk-chip" style="background: ${this._severityColor(riskLevel)}22; color: ${this._severityColor(riskLevel)}; border: 1px solid ${this._severityColor(riskLevel)};">
        Overall Risk: ${riskLevel}
      </div>
      <div class="risk-chip" style="background: #1a1a1a; color: #888; border: 1px solid #333;">
        ${vulns.length} Vulnerabilities Found
      </div>
    </div>
  </div>
</div>

<div class="stats-row">
  <div class="stat-box">
    <div class="stat-number" style="color:#e8e8e8;">${vulns.length}</div>
    <div class="stat-label">Total</div>
  </div>
  <div class="stat-box">
    <div class="stat-number" style="color:#ff2d55;">${counts.CRITICAL}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-box">
    <div class="stat-number" style="color:#ff6b35;">${counts.HIGH}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-box">
    <div class="stat-number" style="color:#ffd60a;">${counts.MEDIUM}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat-box">
    <div class="stat-number" style="color:#30d158;">${counts.LOW}</div>
    <div class="stat-label">Low</div>
  </div>
</div>

<div class="section">
  <div class="section-title">Executive Summary</div>
  <div class="exec-grid">
    <div class="exec-item">
      <div class="exec-item-label">Target Domain</div>
      <div class="exec-item-value">${domain}</div>
    </div>
    <div class="exec-item">
      <div class="exec-item-label">Overall Risk Level</div>
      <div class="exec-item-value" style="color: ${this._severityColor(riskLevel)}">${riskLevel}</div>
    </div>
    <div class="exec-item">
      <div class="exec-item-label">Scan Date</div>
      <div class="exec-item-value">${scanDate}</div>
    </div>
    <div class="exec-item">
      <div class="exec-item-label">Methodology</div>
      <div class="exec-item-value">MoA AI Swarm (NVIDIA + Groq + Cohere)</div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Vulnerability Findings</div>
  ${vulnCards || '<p style="color:#555; text-align:center; padding:40px 0;">No vulnerabilities were confirmed during this scan.</p>'}
</div>

<div class="footer">
  <div>🛡️ Generated by ZerOn Security Scanner — Mixture of Agents AI</div>
  <div>Confidential — For authorized personnel only</div>
</div>

</body>
</html>`;
  }
}

module.exports = PDFReportService;
