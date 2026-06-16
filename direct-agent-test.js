/**
 * ZerOn Direct Agent Test — testfire.net (AltoroMutual Banking App)
 * Accenture's intentionally vulnerable demo bank — confirmed reachable.
 * Known vulns: SQLi in login, XSS in search, Open Redirect in disclaimer,
 *              Missing security headers, weak session handling.
 * Run: node direct-agent-test.js
 */
require('dotenv').config();

const TARGET = 'http://testfire.net';
const SEP  = '═'.repeat(65);
const sep  = '─'.repeat(65);

function sev(s) {
  const m = { Critical:'🔴', High:'🟠', Medium:'🟡', Low:'🔵', Info:'ℹ️' };
  return `${m[s] || '❓'} ${s}`;
}

function printFinding(idx, f) {
  console.log(`\n  [${idx}] ${sev(f.severity)} — ${f.type}`);
  console.log(`       Endpoint : ${f.endpoint}`);
  if (f.parameter) console.log(`       Parameter: ${f.parameter}`);
  if (f.payload && f.payload !== 'Auth Tests')
                   console.log(`       Payload  : ${f.payload}`);
  if (f.cvss)      console.log(`       CVSS     : ${f.cvss}`);
  if (f.cwe)       console.log(`       CWE      : ${f.cwe}`);
  if (f.owasp)     console.log(`       OWASP    : ${f.owasp}`);
  console.log(`       Proof    : ${(f.proof || f.description || '').substring(0, 200)}`);
  if (f.remediation) console.log(`       Fix      : ${(f.remediation || '').substring(0, 150)}`);
}

// ── testfire.net Attack Surface ───────────────────────────────
// Known injectable endpoints for AltoroMutual
const ATTACK_SURFACE = [
  // GET — XSS/SQLi
  { endpoint: { url: `${TARGET}/search.jsp?query=test`,        method: 'GET'  }, parameter: { name: 'query'    } },
  { endpoint: { url: `${TARGET}/bank/main.jsp?panel=transfer`, method: 'GET'  }, parameter: { name: 'panel'    } },
  // POST — login form (known SQLi: admin'-- bypasses auth)
  { endpoint: { url: `${TARGET}/bank/login.aspx`,              method: 'POST' }, parameter: { name: 'uid'      } },
  { endpoint: { url: `${TARGET}/bank/login.aspx`,              method: 'POST' }, parameter: { name: 'passw'    } },
  { endpoint: { url: `${TARGET}/doLogin`,                      method: 'POST' }, parameter: { name: 'uid'      } },
  // Open Redirect
  { endpoint: { url: `${TARGET}/disclaimer.htm?url=https://evil.com`, method: 'GET' }, parameter: { name: 'url' } },
  // SSRF candidates
  { endpoint: { url: `${TARGET}/bank/ws.aspx?src=http://evil.com`, method: 'GET' }, parameter: { name: 'src'  } },
];

// ── MAIN ──────────────────────────────────────────────────────
async function main() {
  console.log('\n' + SEP);
  console.log('  ZerOn MoA — Full Agent Test on testfire.net');
  console.log('  Target: AltoroMutual Demo Bank (Intentionally Vulnerable)');
  console.log('  Testing: SQLi | XSS | Headers | SSRF | Auth | IDOR');
  console.log(SEP);
  console.log(`  Target : ${TARGET}`);
  console.log(`  Started: ${new Date().toISOString()}\n`);

  const allFindings = [];
  const timings = {};

  // ── 1. SQLi Agent ──────────────────────────────────────────
  console.log(sep);
  console.log('  🗡️  [1/6] SQL Injection Agent (NVIDIA Llama 70B)');
  console.log(sep);
  const SqliAgent = require('./services/agents/sqliAgent');
  const sqliStart = Date.now();
  const sqliVectors = ATTACK_SURFACE.filter(v =>
    /uid|query|panel|passw/i.test(v.parameter?.name || '')
  );
  console.log(`  → Testing ${sqliVectors.length} SQLi vectors...`);
  const sqliFindings = await SqliAgent.analyze(sqliVectors, null, 'test');
  timings.sqli = ((Date.now() - sqliStart) / 1000).toFixed(1);
  console.log(`\n  SQLi found: ${sqliFindings.length} vuln(s) in ${timings.sqli}s`);
  sqliFindings.forEach((f, i) => { printFinding(i + 1, f); allFindings.push(f); });

  // ── 2. XSS Agent ───────────────────────────────────────────
  console.log('\n' + sep);
  console.log('  🕸️  [2/6] XSS Agent (Groq Llama 70B)');
  console.log(sep);
  const XssAgent = require('./services/agents/xssAgent');
  const xssStart = Date.now();
  const xssVectors = ATTACK_SURFACE.filter(v =>
    /query|panel|search/i.test(v.parameter?.name || '')
  );
  console.log(`  → Testing ${xssVectors.length} XSS vectors...`);
  const xssFindings = await XssAgent.analyze(xssVectors, null, 'test');
  timings.xss = ((Date.now() - xssStart) / 1000).toFixed(1);
  console.log(`\n  XSS found: ${xssFindings.length} vuln(s) in ${timings.xss}s`);
  xssFindings.forEach((f, i) => { printFinding(i + 1, f); allFindings.push(f); });

  // ── 3. Header Agent ────────────────────────────────────────
  console.log('\n' + sep);
  console.log('  🛡️  [3/6] Header Security Agent (Rule-Based, Zero API Cost)');
  console.log(sep);
  const HeaderAgent = require('./services/agents/headerAgent');
  const headerStart = Date.now();
  console.log(`  → Auditing security headers on ${TARGET}...`);
  const headerFindings = await HeaderAgent.analyze(ATTACK_SURFACE, null, 'test');
  timings.headers = ((Date.now() - headerStart) / 1000).toFixed(1);
  console.log(`\n  Headers found: ${headerFindings.length} issue(s) in ${timings.headers}s`);
  headerFindings.forEach((f, i) => { printFinding(i + 1, f); allFindings.push(f); });

  // ── 4. SSRF / Open Redirect Agent ─────────────────────────
  console.log('\n' + sep);
  console.log('  🌐 [4/6] SSRF & Open Redirect Agent (Cohere Command-R)');
  console.log(sep);
  const SSRFAgent = require('./services/agents/ssrfAgent');
  const ssrfStart = Date.now();
  const ssrfVectors = ATTACK_SURFACE.filter(v =>
    /url|src|redirect|dest|link/i.test(v.parameter?.name || '')
  );
  console.log(`  → Testing ${ssrfVectors.length} SSRF/Redirect vectors...`);
  const ssrfFindings = await SSRFAgent.analyze(ssrfVectors, null, 'test');
  timings.ssrf = ((Date.now() - ssrfStart) / 1000).toFixed(1);
  console.log(`\n  SSRF/Redirect found: ${ssrfFindings.length} vuln(s) in ${timings.ssrf}s`);
  ssrfFindings.forEach((f, i) => { printFinding(i + 1, f); allFindings.push(f); });

  // ── 5. Auth Agent ──────────────────────────────────────────
  console.log('\n' + sep);
  console.log('  🔑 [5/6] Authentication Failures Agent (Mistral AI)');
  console.log(sep);
  const AuthAgent = require('./services/agents/authAgent');
  const authStart = Date.now();
  const authVectors = ATTACK_SURFACE.filter(v =>
    /uid|passw|username|email|password/i.test(v.parameter?.name || '') ||
    v.endpoint?.url.toLowerCase().includes('login')
  );
  console.log(`  → Testing ${authVectors.length} Auth vectors...`);
  const authFindings = await AuthAgent.analyze(authVectors, null, 'test');
  timings.auth = ((Date.now() - authStart) / 1000).toFixed(1);
  console.log(`\n  Auth found: ${authFindings.length} vuln(s) in ${timings.auth}s`);
  authFindings.forEach((f, i) => { printFinding(i + 1, f); allFindings.push(f); });

  // ── 6. IDOR Agent ──────────────────────────────────────────
  console.log('\n' + sep);
  console.log('  🔓 [6/6] IDOR / Broken Access Control Agent (Groq)');
  console.log(sep);
  const IdorAgent = require('./services/agents/idorAgent');
  const idorStart = Date.now();
  const idorVectors = ATTACK_SURFACE.filter(v =>
    /id|uid|account|order|profile|doc|panel/i.test(v.parameter?.name || '')
  );
  console.log(`  → Testing ${idorVectors.length} IDOR vectors...`);
  const idorFindings = await IdorAgent.analyze(idorVectors, null, 'test');
  timings.idor = ((Date.now() - idorStart) / 1000).toFixed(1);
  console.log(`\n  IDOR found: ${idorFindings.length} vuln(s) in ${timings.idor}s`);
  idorFindings.forEach((f, i) => { printFinding(i + 1, f); allFindings.push(f); });

  // ── SUMMARY ────────────────────────────────────────────────
  console.log('\n\n' + SEP);
  console.log('  📊 FULL SCAN RESULTS SUMMARY — testfire.net');
  console.log(SEP);

  const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const byType = {};
  for (const f of allFindings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byType[f.type] = (byType[f.type] || 0) + 1;
  }

  console.log(`\n  Total Confirmed Vulnerabilities: ${allFindings.length}`);
  console.log(`\n  By Severity:`);
  console.log(`    🔴 Critical : ${bySeverity.Critical}`);
  console.log(`    🟠 High     : ${bySeverity.High}`);
  console.log(`    🟡 Medium   : ${bySeverity.Medium}`);
  console.log(`    🔵 Low      : ${bySeverity.Low}`);

  if (Object.keys(byType).length > 0) {
    console.log(`\n  By Type:`);
    for (const [type, count] of Object.entries(byType)) {
      console.log(`    • ${type} : ${count}`);
    }
  }

  console.log(`\n  Agent Performance:`);
  for (const [agent, time] of Object.entries(timings)) {
    console.log(`    ${agent.padEnd(10)}: ${time}s`);
  }

  console.log(`\n  Finished: ${new Date().toISOString()}`);
  console.log(SEP + '\n');
}

main().catch(e => {
  console.error('\nFatal Error:', e.message);
  process.exit(1);
});
