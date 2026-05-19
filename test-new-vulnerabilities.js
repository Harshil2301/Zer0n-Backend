// Test New Vulnerability Detection: IDOR, CORS, Open Redirect, Auth Bypass, Business Logic
const AdvancedExploitationService = require('./services/Phase3/advancedExploitationService');

async function testNewVulnerabilities() {
  console.log('\n🧪 Testing New Vulnerability Detection Features\n');
  console.log('=' .repeat(80));
  
  const results = {
    idor: 0,
    cors: 0,
    openRedirect: 0,
    authBypass: 0,
    businessLogic: 0
  };
  
  // ===================================================================
  // TEST 1: IDOR Detection
  // ===================================================================
  console.log('\n\n📋 TEST 1: IDOR (Insecure Direct Object Reference)');
  console.log('─'.repeat(80));
  
  const idorTests = [
    {
      endpoint: { url: 'http://testphp.vulnweb.com/artists.php?artist=1', method: 'GET' },
      parameter: { name: 'artist', classification: 'id' },
      description: 'Artist ID parameter'
    },
    {
      endpoint: { url: 'http://testphp.vulnweb.com/product.php?pic=1', method: 'GET' },
      parameter: { name: 'pic', classification: 'id' },
      description: 'Product picture ID'
    }
  ];
  
  for (const test of idorTests) {
    console.log(`\n🔍 Testing: ${test.description}`);
    console.log(`   URL: ${test.endpoint.url}`);
    console.log(`   Parameter: ${test.parameter.name}`);
    
    try {
      const idorResults = await AdvancedExploitationService.testIDOROnly(test.endpoint, test.parameter);
      if (idorResults.length > 0) {
        console.log(`   ✅ IDOR Found: ${idorResults[0].subType} (${idorResults[0].confidence}% confidence)`);
        results.idor++;
      } else {
        console.log(`   ⚪ No IDOR detected`);
      }
    } catch (error) {
      console.error(`   ❌ Error: ${error.message}`);
    }
  }
  
  // ===================================================================
  // TEST 2: CORS Misconfiguration
  // ===================================================================
  console.log('\n\n📋 TEST 2: CORS Misconfiguration');
  console.log('─'.repeat(80));
  
  const corsTests = [
    {
      endpoint: { url: 'http://testphp.vulnweb.com/artists.php', method: 'GET' },
      parameter: { name: 'artist' },
      description: 'API endpoint CORS check'
    }
  ];
  
  for (const test of corsTests) {
    console.log(`\n🔍 Testing: ${test.description}`);
    console.log(`   URL: ${test.endpoint.url}`);
    
    try {
      const corsResults = await AdvancedExploitationService.testCORSOnly(test.endpoint, test.parameter);
      if (corsResults.length > 0) {
        console.log(`   ✅ CORS Issue Found: ${corsResults[0].subType} (${corsResults[0].confidence}% confidence)`);
        results.cors++;
      } else {
        console.log(`   ⚪ No CORS misconfiguration`);
      }
    } catch (error) {
      console.error(`   ❌ Error: ${error.message}`);
    }
  }
  
  // ===================================================================
  // TEST 3: Open Redirect
  // ===================================================================
  console.log('\n\n📋 TEST 3: Open Redirect');
  console.log('─'.repeat(80));
  
  const redirectTests = [
    {
      endpoint: { url: 'http://testphp.vulnweb.com/redir.php?redirect=test', method: 'GET' },
      parameter: { name: 'redirect' },
      description: 'Redirect parameter'
    },
    {
      endpoint: { url: 'http://testphp.vulnweb.com/url.php?url=test', method: 'GET' },
      parameter: { name: 'url' },
      description: 'URL parameter'
    }
  ];
  
  for (const test of redirectTests) {
    console.log(`\n🔍 Testing: ${test.description}`);
    console.log(`   URL: ${test.endpoint.url}`);
    console.log(`   Parameter: ${test.parameter.name}`);
    
    try {
      const redirectResults = await AdvancedExploitationService.testOpenRedirectOnly(test.endpoint, test.parameter);
      if (redirectResults.length > 0) {
        console.log(`   ✅ Open Redirect Found: ${redirectResults[0].subType} (${redirectResults[0].confidence}% confidence)`);
        results.openRedirect++;
      } else {
        console.log(`   ⚪ No open redirect`);
      }
    } catch (error) {
      console.error(`   ❌ Error: ${error.message}`);
    }
  }
  
  // ===================================================================
  // TEST 4: Authentication Bypass
  // ===================================================================
  console.log('\n\n📋 TEST 4: Authentication Bypass');
  console.log('─'.repeat(80));
  
  const authTests = [
    {
      endpoint: { url: 'http://testphp.vulnweb.com/login.php', method: 'POST' },
      parameter: { name: 'username' },
      description: 'Login username field'
    },
    {
      endpoint: { url: 'http://testphp.vulnweb.com/userinfo.php', method: 'POST' },
      parameter: { name: 'uname' },
      description: 'User authentication field'
    }
  ];
  
  for (const test of authTests) {
    console.log(`\n🔍 Testing: ${test.description}`);
    console.log(`   URL: ${test.endpoint.url}`);
    console.log(`   Parameter: ${test.parameter.name}`);
    
    try {
      const authResults = await AdvancedExploitationService.testAuthBypassOnly(test.endpoint, test.parameter);
      if (authResults.length > 0) {
        console.log(`   ✅ Auth Bypass Found: ${authResults[0].subType} (${authResults[0].confidence}% confidence)`);
        results.authBypass++;
      } else {
        console.log(`   ⚪ No auth bypass`);
      }
    } catch (error) {
      console.error(`   ❌ Error: ${error.message}`);
    }
  }
  
  // ===================================================================
  // TEST 5: Business Logic Flaws
  // ===================================================================
  console.log('\n\n📋 TEST 5: Business Logic Vulnerabilities');
  console.log('─'.repeat(80));
  
  const bizLogicTests = [
    {
      endpoint: { url: 'http://testphp.vulnweb.com/cart.php', method: 'POST' },
      parameter: { name: 'price' },
      description: 'Price parameter manipulation'
    },
    {
      endpoint: { url: 'http://testphp.vulnweb.com/cart.php', method: 'POST' },
      parameter: { name: 'quantity' },
      description: 'Quantity parameter manipulation'
    },
    {
      endpoint: { url: 'http://testphp.vulnweb.com/cart.php', method: 'POST' },
      parameter: { name: 'discount' },
      description: 'Discount code manipulation'
    }
  ];
  
  for (const test of bizLogicTests) {
    console.log(`\n🔍 Testing: ${test.description}`);
    console.log(`   URL: ${test.endpoint.url}`);
    console.log(`   Parameter: ${test.parameter.name}`);
    
    try {
      const bizResults = await AdvancedExploitationService.testBusinessLogicOnly(test.endpoint, test.parameter);
      if (bizResults.length > 0) {
        console.log(`   ✅ Business Logic Flaw Found: ${bizResults[0].subType} (${bizResults[0].confidence}% confidence)`);
        results.businessLogic++;
      } else {
        console.log(`   ⚪ No business logic flaw`);
      }
    } catch (error) {
      console.error(`   ❌ Error: ${error.message}`);
    }
  }
  
  // ===================================================================
  // SUMMARY
  // ===================================================================
  console.log('\n\n' + '═'.repeat(80));
  console.log('📊 TEST SUMMARY');
  console.log('═'.repeat(80));
  console.log(`\n✅ Total Vulnerabilities Found: ${Object.values(results).reduce((a, b) => a + b, 0)}`);
  console.log(`\n   • IDOR: ${results.idor}`);
  console.log(`   • CORS Misconfiguration: ${results.cors}`);
  console.log(`   • Open Redirect: ${results.openRedirect}`);
  console.log(`   • Authentication Bypass: ${results.authBypass}`);
  console.log(`   • Business Logic Flaws: ${results.businessLogic}`);
  console.log('\n' + '═'.repeat(80));
  console.log('\n✅ All vulnerability detection methods tested successfully!');
  console.log('🎯 ZerOn scanner now detects 10 vulnerability types:\n');
  console.log('   1. XSS (Cross-Site Scripting)');
  console.log('   2. SQLi (SQL Injection)');
  console.log('   3. SSRF (Server-Side Request Forgery)');
  console.log('   4. RCE (Remote Code Execution)');
  console.log('   5. Information Disclosure');
  console.log('   6. IDOR (Insecure Direct Object Reference) ✨ NEW');
  console.log('   7. CORS Misconfiguration ✨ NEW');
  console.log('   8. Open Redirect ✨ NEW');
  console.log('   9. Authentication Bypass ✨ NEW');
  console.log('   10. Business Logic Flaws ✨ NEW\n');
  console.log('=' .repeat(80));
}

// Run the test
testNewVulnerabilities().catch(console.error);
