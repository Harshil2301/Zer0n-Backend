/**
 * ZerOn Backend - Full Pipeline Test
 * Tests every component from Phase 0 → Phase 4 before a real scan
 * Run: node pipeline-test.js
 */
require('dotenv').config();

const PASS = '✅ PASS';
const FAIL = '❌ FAIL';
const WARN = '⚠️  WARN';

let totalPass = 0, totalFail = 0, totalWarn = 0;

function result(label, ok, detail = '', warn = false) {
  if (warn) { console.log(`  ${WARN}  ${label}${detail ? ' — ' + detail : ''}`); totalWarn++; }
  else if (ok) { console.log(`  ${PASS}  ${label}${detail ? ' — ' + detail : ''}`); totalPass++; }
  else { console.log(`  ${FAIL}  ${label}${detail ? ' — ' + detail : ''}`); totalFail++; }
}

// ============================================================
// 1. ENV / API KEY CHECK
// ============================================================
async function checkEnv() {
  console.log('\n📋 [1/7] Environment & API Key Check');
  const required = {
    GEMINI_API_KEY:    process.env.GEMINI_API_KEY,
    NVIDIA_API_KEY:    process.env.NVIDIA_API_KEY,
    GROQ_API_KEY:      process.env.GROQ_API_KEY,
    COHERE_API_KEY:    process.env.COHERE_API_KEY,
    CEREBRAS_API_KEY:  process.env.CEREBRAS_API_KEY,
  };
  for (const [key, val] of Object.entries(required)) {
    result(key, !!val, val ? `${val.substring(0, 8)}...` : 'MISSING');
  }
}

// ============================================================
// 2. PHASE 2 — PARAMETER DISCOVERY
// ============================================================
async function checkPhase2() {
  console.log('\n🔍 [2/7] Phase 2 — Parameter Discovery');
  const ParameterDiscovery = require('./services/Phase2/parameterDiscovery');
  
  // Test 1: URL query params
  const r1 = await ParameterDiscovery.discoverParameters('http://testfire.net/search.jsp?query=hello');
  result('URL query param extraction', r1.parameters.some(p => p.name === 'query'), `Found params: ${r1.parameters.map(p=>p.name).join(', ')}`);
  
  // Test 2: Form field extraction (doLogin should have uid, passw)
  const r2 = await ParameterDiscovery.discoverParameters('http://testfire.net/login.jsp');
  const hasUid   = r2.parameters.some(p => p.name === 'uid');
  const hasPassw = r2.parameters.some(p => p.name === 'passw');
  result('Form field: uid',   hasUid,   `All found: ${r2.parameters.map(p=>p.name).join(', ')}`);
  result('Form field: passw', hasPassw, `All found: ${r2.parameters.map(p=>p.name).join(', ')}`);
  
  // Test 3: getInjectableParameters includes passw now
  const injectable = ParameterDiscovery.getInjectableParameters(r2.parameters);
  const passwIncluded = injectable.some(p => p.name === 'passw');
  result('passw included in injectable', passwIncluded, `Injectable: ${injectable.map(p=>p.name).join(', ')}`);
}

// ============================================================
// 3. NVIDIA API — SQLi Payload Generation
// ============================================================
async function checkNVIDIA() {
  console.log('\n🤖 [3/7] NVIDIA API — SQLi Payload Generation');
  try {
    const res = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.NVIDIA_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'meta/llama-3.1-8b-instruct',
        messages: [{ role: 'user', content: 'Return ONLY this JSON array, nothing else: ["\' OR 1=1--", "admin\'--"]' }],
        max_tokens: 80, temperature: 0, stream: false
      })
    });
    const data = await res.json();
    const text = data.choices?.[0]?.message?.content || '';
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    const payloads = jsonMatch ? JSON.parse(jsonMatch[0]) : null;
    result('NVIDIA API reachable', res.ok, `HTTP ${res.status}`);
    result('NVIDIA returns JSON array', Array.isArray(payloads), `Payloads: ${JSON.stringify(payloads)}`);
  } catch (e) {
    result('NVIDIA API', false, e.message);
  }
}

// ============================================================
// 4. GROQ API — XSS Payload Generation  
// ============================================================
async function checkGroq() {
  console.log('\n🤖 [4/7] Groq API — XSS Payload Generation');
  try {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: 'Return ONLY this JSON array: ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]' }],
        max_tokens: 80, temperature: 0
      })
    });
    const data = await res.json();
    const text = data.choices?.[0]?.message?.content || '';
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    const payloads = jsonMatch ? JSON.parse(jsonMatch[0]) : null;
    result('Groq API reachable', res.ok, `HTTP ${res.status}`);
    result('Groq returns JSON array', Array.isArray(payloads), `Payloads: ${JSON.stringify(payloads)}`);
  } catch (e) {
    result('Groq API', false, e.message);
  }
}

// ============================================================
// 4.5. COHERE API — SSRF Payload Generation
// ============================================================
async function checkCohere() {
  console.log('\n🤖 [4.5/7] Cohere API — SSRF Payload Generation');
  try {
    const res = await fetch('https://api.cohere.com/v1/chat', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.COHERE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'command-r-08-2024',
        message: 'Return ONLY valid JSON like this: {"ssrf_payloads":["http://127.0.0.1"]}',
        max_tokens: 80, temperature: 0
      })
    });
    const data = await res.json();
    const text = data.text || '{}';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    const payloads = jsonMatch ? JSON.parse(jsonMatch[0]) : null;
    result('Cohere API reachable', res.ok, `HTTP ${res.status}`);
    result('Cohere returns JSON object', payloads && Array.isArray(payloads.ssrf_payloads), `Payloads: ${JSON.stringify(payloads)}`);
  } catch (e) {
    result('Cohere API', false, e.message);
  }
}

// ============================================================
// 5. REAL HTTP ATTACK TESTS
// ============================================================
async function checkAttacks() {
  console.log('\n🎯 [5/7] Real HTTP Attack Tests on testfire.net');

  // XSS reflection test
  try {
    const payload = '<script>alert(1)</script>';
    const r = await fetch(`http://testfire.net/search.jsp?query=${encodeURIComponent(payload)}`, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const body = await r.text();
    result('XSS payload reflects in search.jsp', body.includes(payload), `HTTP ${r.status}`);
  } catch (e) { result('XSS reflection test', false, e.message); }

  // IMG XSS test
  try {
    const payload = '<img src=x onerror=alert(1)>';
    const r = await fetch(`http://testfire.net/search.jsp?query=${encodeURIComponent(payload)}`, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const body = await r.text();
    result('IMG XSS payload reflects in search.jsp', body.includes(payload), `HTTP ${r.status}`);
  } catch (e) { result('IMG XSS test', false, e.message); }

  // Header detection test
  try {
    const r = await fetch('http://testfire.net', { method: 'HEAD', headers: { 'User-Agent': 'Mozilla/5.0' } });
    const hasCSP = r.headers.get('content-security-policy');
    const hasHSTS = r.headers.get('strict-transport-security');
    result('Missing CSP header detected', !hasCSP, `CSP present: ${!!hasCSP}`);
    result('Missing HSTS header detected', !hasHSTS, `HSTS present: ${!!hasHSTS}`);
  } catch (e) { result('Header detection', false, e.message); }

  // Boolean-blind SQLi test
  try {
    const trueRes  = await fetch(`http://testfire.net/search.jsp?query=${encodeURIComponent("' OR '1'='1")}`,  { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const falseRes = await fetch(`http://testfire.net/search.jsp?query=${encodeURIComponent("' OR '1'='2")}`, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const [trueBody, falseBody] = await Promise.all([trueRes.text(), falseRes.text()]);
    const diff = Math.abs(trueBody.length - falseBody.length);
    result('SQLi boolean-blind detectable', diff > 100, `Diff: ${diff} bytes (need >100)`, diff <= 100);
  } catch (e) { result('SQLi blind test', false, e.message); }
}

// ============================================================
// 6. CEREBRAS — Reflection Loop Test
// ============================================================
async function checkCerebras() {
  console.log('\n🧠 [6/7] Cerebras — Reflection Loop Judge Test');
  try {
    const res = await fetch('https://api.cerebras.ai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${process.env.CEREBRAS_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'gpt-oss-120b',
        messages: [{ role: 'user', content: 'Respond ONLY with this exact JSON: {"isConfirmed": true, "reason": "test passed"}' }],
        max_tokens: 60, temperature: 0
      })
    });
    const data = await res.json();
    const text = data.choices?.[0]?.message?.content?.trim() || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    const verdict = jsonMatch ? JSON.parse(jsonMatch[0]) : null;
    if (!verdict) console.log('Raw text:', text);
    result('Cerebras API reachable', res.ok, `HTTP ${res.status}`);
    result('Cerebras returns valid JSON', verdict?.isConfirmed === true, `Verdict: ${JSON.stringify(verdict)}`, verdict?.isConfirmed !== true);
  } catch (e) {
    result('Cerebras API', false, e.message);
  }
}

// ============================================================
// 7. PHASE 4 — Report Generator Test
// ============================================================
async function checkPhase4() {
  console.log('\n📊 [7/7] Phase 4 — Report Generator Test');
  try {
    const BugBountyReportService = require('./services/Phase4/bugBountyReportService');
    const ReportGenerator = require('./services/Phase4/reportGenerator');

    const mockVuln = {
      id: 'test_001', type: 'Cross-Site Scripting (XSS)', severity: 'high', cvss: 7.5,
      endpoint: 'http://testfire.net/search.jsp', parameter: 'query',
      description: 'XSS found', payload: '<script>alert(1)</script>',
      confidence: 95, indicators: ['payload reflected'], poc: 'curl test',
      request: { method: 'GET', url: 'http://testfire.net/search.jsp', parameter: 'query', value: '<script>alert(1)</script>' },
      response: { status: 200, snippet: '<script>alert(1)</script>' },
      discoveredAt: new Date().toISOString()
    };

    const bbReport = BugBountyReportService.generateBugBountyReport(mockVuln);
    result('BugBountyReportService works', !!bbReport?.title, `Title: ${bbReport?.title}`);

    const markdown = BugBountyReportService.generateMarkdownReport(mockVuln);
    result('Markdown report generated', markdown?.length > 50, `Length: ${markdown?.length} chars`);

    const execReport = ReportGenerator.generateReport([mockVuln], { domain: 'testfire.net', duration: 60000, scanId: 'test' });
    result('Executive report generated', !!execReport?.executive_summary, `Risk: ${execReport?.executive_summary?.risk_level}`);
  } catch (e) {
    result('Phase 4 report generation', false, e.message);
  }
}

// ============================================================
// RUN ALL CHECKS
// ============================================================
async function runAll() {
  console.log('\n' + '='.repeat(60));
  console.log('🎯 ZerOn Backend — Full Pipeline Validation');
  console.log('='.repeat(60));

  await checkEnv();
  await checkPhase2();
  await checkNVIDIA();
  await checkGroq();
  await checkCohere();
  await checkAttacks();
  await checkCerebras();
  await checkPhase4();

  console.log('\n' + '='.repeat(60));
  console.log(`📊 Results: ${totalPass} passed | ${totalFail} failed | ${totalWarn} warnings`);
  console.log('='.repeat(60));
  
  if (totalFail === 0) {
    console.log('\n✅ All critical checks passed. Pipeline is ready for scanning!\n');
  } else {
    console.log(`\n❌ ${totalFail} critical issue(s) found. Fix them before scanning.\n`);
    process.exit(1);
  }
}

runAll().catch(e => { console.error('\nFatal test error:', e); process.exit(1); });
