/**
 * ZerOn Notification Service
 * 
 * Fires on scan completion:
 *  1. Webhook — POST to any URL the user configured in Settings
 *  2. Email   — Sends a professional scan summary via Gmail SMTP (nodemailer)
 * 
 * Both channels are completely optional.
 * If the user has not configured them, the calls are silent no-ops.
 * If credentials are missing in .env, both channels are skipped gracefully.
 */

const nodemailer = require('nodemailer');

class NotificationService {
  constructor() {
    // Build a nodemailer transporter only if SMTP credentials are provided
    if (process.env.SMTP_EMAIL && process.env.SMTP_PASSWORD) {
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.SMTP_EMAIL,
          pass: process.env.SMTP_PASSWORD  // Use an App Password, not your main Gmail password
        }
      });
      console.log('[Notifications] ✓ Email transporter ready');
    } else {
      this.transporter = null;
      console.log('[Notifications] ℹ Email transporter not configured (SMTP_EMAIL / SMTP_PASSWORD not set). Email notifications disabled.');
    }
  }

  /**
   * Fire webhook if the user has one configured
   * @param {string} userId - Firebase user ID
   * @param {object} db - Firestore instance
   * @param {object} scanData - completed scan data
   */
  async fireWebhook(userId, db, scanData) {
    if (!userId || userId === 'anonymous') return;
    try {
      const userDoc = await db.collection('users').doc(userId).get();
      if (!userDoc.exists) return;

      const webhookUrl = userDoc.data()?.notifications?.webhookUrl;
      if (!webhookUrl || !webhookUrl.startsWith('http')) return;

      const payload = {
        event: 'scan_complete',
        scanId: scanData.scanId,
        domain: scanData.domain,
        completedAt: new Date().toISOString(),
        summary: {
          totalVulnerabilities: scanData.vulnerabilities?.length || 0,
          critical: (scanData.vulnerabilities || []).filter(v => (v.severity || '').toLowerCase() === 'critical').length,
          high:     (scanData.vulnerabilities || []).filter(v => (v.severity || '').toLowerCase() === 'high').length,
          medium:   (scanData.vulnerabilities || []).filter(v => (v.severity || '').toLowerCase() === 'medium').length,
          low:      (scanData.vulnerabilities || []).filter(v => (v.severity || '').toLowerCase() === 'low').length,
          estimatedBounty: scanData.estimatedBounty?.total || 0
        }
      };

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout

      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'ZerOn-Scanner/1.0' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timeout);

      console.log(`[Webhook] ✓ Notified ${webhookUrl} for scan ${scanData.scanId}`);
    } catch (e) {
      // Never crash the scan pipeline because of a webhook failure
      console.warn(`[Webhook] ⚠ Failed to fire webhook for user ${userId}: ${e.message}`);
    }
  }

  /**
   * Send scan complete email if user has email alerts enabled
   * @param {string} userId - Firebase user ID
   * @param {object} db - Firestore instance
   * @param {object} scanData - completed scan data
   */
  async fireEmail(userId, db, scanData) {
    if (!this.transporter) return;
    if (!userId || userId === 'anonymous') return;

    try {
      const userDoc = await db.collection('users').doc(userId).get();
      if (!userDoc.exists) return;

      const userData = userDoc.data();
      // Default to true unless explicitly disabled
      const scanAlerts = userData?.notifications?.scanAlerts !== false; 
      // Check both profile.email and root email
      const email = userData?.profile?.email || userData?.email;

      // Respect the user's notification preference
      if (!scanAlerts || !email) {
        console.log(`[Email] Skipping scan complete email for ${userId}. alertsEnabled=${scanAlerts}, hasEmail=${!!email}`);
        return;
      }

      const vulns = scanData.vulnerabilities || [];
      const critical = vulns.filter(v => (v.severity || '').toLowerCase() === 'critical').length;
      const high     = vulns.filter(v => (v.severity || '').toLowerCase() === 'high').length;
      const medium   = vulns.filter(v => (v.severity || '').toLowerCase() === 'medium').length;
      const low      = vulns.filter(v => (v.severity || '').toLowerCase() === 'low').length;
      const bounty   = scanData.estimatedBounty?.total || 0;

      const riskColor = critical > 0 ? '#ff2d55' : high > 0 ? '#ff6b35' : medium > 0 ? '#ffd60a' : '#30d158';
      const riskLabel = critical > 0 ? 'CRITICAL' : high > 0 ? 'HIGH' : medium > 0 ? 'MEDIUM' : 'LOW';

      const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0d0d0d;font-family:'Segoe UI',Arial,sans-serif;color:#e8e8e8;">
  <div style="max-width:600px;margin:0 auto;padding:24px;">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0d0d0d,#1a0a2e);border:1px solid #222;border-bottom:2px solid #00ff88;border-radius:12px 12px 0 0;padding:32px 32px 24px;">
      <div style="font-size:24px;font-weight:900;letter-spacing:4px;color:#00ff88;">ZER<span style="color:#00d4ff;">ON</span></div>
      <div style="font-size:11px;color:#888;letter-spacing:3px;text-transform:uppercase;margin-top:4px;">Vulnerability Scanner — Scan Complete</div>
    </div>

    <!-- Body -->
    <div style="background:#111;border:1px solid #222;border-top:none;padding:32px;">
      <h2 style="font-size:20px;color:#fff;margin:0 0 8px;">Scan Completed for <span style="color:#00d4ff;">${scanData.domain}</span></h2>
      <p style="color:#888;font-size:13px;margin:0 0 24px;">Your AI-powered vulnerability assessment has finished.</p>

      <!-- Risk Banner -->
      <div style="display:inline-block;background:${riskColor}22;border:1px solid ${riskColor};border-radius:20px;padding:6px 18px;margin-bottom:24px;">
        <span style="color:${riskColor};font-weight:700;font-size:13px;letter-spacing:1px;">Assessment Level: ${riskLabel}</span>
      </div>

      <!-- Stats Grid -->
      <table width="100%" cellpadding="0" cellspacing="12" style="margin-bottom:24px;">
        <tr>
          <td style="background:#1a1a1a;border-radius:8px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:900;color:#e8e8e8;">${vulns.length}</div>
            <div style="font-size:10px;letter-spacing:2px;color:#888;text-transform:uppercase;margin-top:4px;">Total</div>
          </td>
          <td style="background:#1a1a1a;border-radius:8px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:900;color:#ff2d55;">${critical}</div>
            <div style="font-size:10px;letter-spacing:2px;color:#888;text-transform:uppercase;margin-top:4px;">Critical</div>
          </td>
          <td style="background:#1a1a1a;border-radius:8px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:900;color:#ff6b35;">${high}</div>
            <div style="font-size:10px;letter-spacing:2px;color:#888;text-transform:uppercase;margin-top:4px;">High</div>
          </td>
          <td style="background:#1a1a1a;border-radius:8px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:900;color:#ffd60a;">${medium}</div>
            <div style="font-size:10px;letter-spacing:2px;color:#888;text-transform:uppercase;margin-top:4px;">Medium</div>
          </td>
          <td style="background:#1a1a1a;border-radius:8px;padding:16px;text-align:center;">
            <div style="font-size:28px;font-weight:900;color:#30d158;">${low}</div>
            <div style="font-size:10px;letter-spacing:2px;color:#888;text-transform:uppercase;margin-top:4px;">Low</div>
          </td>
        </tr>
      </table>

      ${bounty > 0 ? `
      <!-- Bounty -->
      <div style="background:rgba(0,255,136,0.06);border:1px solid #00ff88;border-radius:8px;padding:16px;margin-bottom:24px;">
        <div style="font-size:11px;letter-spacing:2px;color:#00ff88;text-transform:uppercase;">Estimated Bug Bounty Value</div>
        <div style="font-size:28px;font-weight:900;color:#00ff88;margin-top:4px;">$${bounty.toLocaleString()}</div>
      </div>` : ''}

      <!-- CTA -->
      <div style="text-align:center;margin-top:24px;">
        <a href="https://zer0n.vercel.app/report/${scanData.scanId}" style="background:linear-gradient(135deg,#00ff88,#00d4ff);color:#000;font-weight:700;font-size:14px;padding:14px 32px;border-radius:8px;text-decoration:none;letter-spacing:1px;display:inline-block;">View Public Report →</a>
      </div>
    </div>

    <!-- Footer -->
    <div style="background:#0a0a0a;border:1px solid #222;border-top:none;border-radius:0 0 12px 12px;padding:16px 32px;text-align:center;">
      <div style="color:#555;font-size:11px;">🛡️ ZerOn Security Scanner — AI-Powered Penetration Testing</div>
      <div style="color:#333;font-size:10px;margin-top:4px;">To disable these emails, go to Settings → Notifications → Scan Alerts</div>
    </div>

  </div>
</body>
</html>`;

      await this.transporter.sendMail({
        from: `"ZerOn Platform" <${process.env.SMTP_EMAIL}>`,
        to: email,
        subject: `ZerOn Assessment Completed: ${scanData.domain}`,
        text: `Scan Completed for ${scanData.domain}. Assessment Level: ${riskLabel}. Findings: ${critical} Critical, ${high} High, ${medium} Medium, ${low} Low. View your full report at https://zer0n.vercel.app/report/${scanData.scanId}`,
        html
      });

      console.log(`[Email] ✓ Scan complete email sent to ${email} for scan ${scanData.scanId}`);
    } catch (e) {
      // Never crash the scan pipeline because of an email failure
      console.warn(`[Email] ⚠ Failed to send email for user ${userId}: ${e.message}`);
    }
  }

  /**
   * Fire all notifications for a completed scan
   * Convenience method that calls both webhook + email in parallel
   */
  async notifyScanComplete(userId, db, scanData) {
    await Promise.allSettled([
      this.fireWebhook(userId, db, scanData),
      this.fireEmail(userId, db, scanData)
    ]);
  }
  async sendWelcomeEmail(email, fullName) {
    if (!this.transporter) return;
    if (!email) return;

    try {
      const html = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0d0d0d;font-family:'Segoe UI',Arial,sans-serif;color:#e8e8e8;">
  <div style="max-width:600px;margin:0 auto;padding:24px;">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#0d0d0d,#1a0a2e);border:1px solid #222;border-bottom:2px solid #00ff88;border-radius:12px 12px 0 0;padding:32px 32px 24px;">
      <div style="font-size:24px;font-weight:900;letter-spacing:4px;color:#00ff88;">ZER<span style="color:#00d4ff;">ON</span></div>
      <div style="font-size:11px;color:#888;letter-spacing:3px;text-transform:uppercase;margin-top:4px;">Security Platform — Welcome Aboard</div>
    </div>

    <!-- Body -->
    <div style="background:#111;border:1px solid #222;border-top:none;padding:32px;">
      <h2 style="font-size:20px;color:#fff;margin:0 0 16px;">Welcome to ZerOn, <span style="color:#00d4ff;">${fullName || 'Security Analyst'}</span>!</h2>
      <p style="color:#aaa;font-size:14px;line-height:1.6;margin:0 0 24px;">
        Your biometric identity has been securely verified and your account is ready. You now have access to our AI-powered Vulnerability Assessment and Penetration Testing engine.
      </p>

      <div style="background:rgba(0,255,136,0.06);border:1px solid rgba(0,255,136,0.3);border-radius:8px;padding:16px;margin-bottom:24px;">
        <h3 style="color:#00ff88;font-size:14px;margin:0 0 8px;">🚀 Quick Start Guide</h3>
        <ul style="color:#ddd;font-size:13px;line-height:1.8;margin:0;padding-left:20px;">
          <li>Navigate to the <b>Dashboard</b> to view your active plan.</li>
          <li>Click <b>New Scan</b> to launch an AI red-team attack on your domains.</li>
          <li>Configure <b>Threat Intel</b> feeds to stay updated on zero-days.</li>
        </ul>
      </div>

      <!-- CTA -->
      <div style="text-align:center;margin-top:32px;margin-bottom:16px;">
        <a href="https://zer0n.vercel.app/dashboard" style="background:linear-gradient(135deg,#00ff88,#00d4ff);color:#000;font-weight:700;font-size:14px;padding:14px 32px;border-radius:8px;text-decoration:none;letter-spacing:1px;display:inline-block;">Go to Dashboard →</a>
      </div>
    </div>

    <!-- Footer -->
    <div style="background:#0a0a0a;border:1px solid #222;border-top:none;border-radius:0 0 12px 12px;padding:16px 32px;text-align:center;">
      <div style="color:#555;font-size:11px;">🛡️ ZerOn Security Scanner — AI-Powered Penetration Testing</div>
    </div>

  </div>
</body>
</html>`;

      await this.transporter.sendMail({
        from: `"ZerOn Platform" <${process.env.SMTP_EMAIL}>`,
        to: email,
        subject: `Welcome to ZerOn Security, ${fullName || 'Analyst'}!`,
        text: `Welcome to ZerOn, ${fullName || 'Security Analyst'}! Your biometric identity has been securely verified and your account is ready. Navigate to the Dashboard to view your active plan and launch an assessment. Go to Dashboard: https://zer0n.vercel.app/dashboard`,
        html
      });

      console.log(`[Email] ✓ Welcome email sent to ${email}`);
    } catch (e) {
      console.warn(`[Email] ⚠ Failed to send welcome email to ${email}: ${e.message}`);
    }
  }
}

module.exports = new NotificationService();
