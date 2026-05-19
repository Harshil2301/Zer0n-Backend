// Test Phase 3: Advanced Exploitation
const AdvancedExploitationService = require('./services/Phase3/advancedExploitationService');

async function testPhase3() {
  console.log('🧪 Testing Phase 3: Advanced Exploitation\n');
  
  // Test XSS detection
  const endpoint = {
    url: 'http://testphp.vulnweb.com/listproducts.php?cat=1',
    method: 'GET'
  };
  
  const parameter = {
    name: 'cat',
    value: '1',
    riskLevel: 'medium',
    recommendedTests: ['XSS', 'SQLi']
  };
  
  console.log(`🎯 Testing Endpoint: ${endpoint.url}`);
  console.log(`📌 Parameter: ${parameter.name}\n`);
  
  // Test XSS
  console.log('🔍 Testing XSS vulnerabilities...');
  const xssResults = await AdvancedExploitationService.testXSSOnly(endpoint, parameter);
  console.log(`   Found ${xssResults.length} XSS vulnerabilities`);
  xssResults.forEach((result, i) => {
    console.log(`   ${i+1}. ${result.type} - Confidence: ${result.confidence}%`);
    if (result.payload && typeof result.payload === 'string') {
      console.log(`      Payload: ${result.payload.substring(0, 80)}...`);
    }
    if (result.evidence) {
      console.log(`      Evidence: ${JSON.stringify(result.evidence).substring(0, 80)}...`);
    }
  });
  
  // Test SQLi
  console.log('\n🔍 Testing SQL Injection vulnerabilities...');
  const sqliResults = await AdvancedExploitationService.testSQLiOnly(endpoint, parameter);
  console.log(`   Found ${sqliResults.length} SQLi vulnerabilities`);
  sqliResults.forEach((result, i) => {
    console.log(`   ${i+1}. ${result.type} - Confidence: ${result.confidence}%`);
    if (result.payload && typeof result.payload === 'string') {
      console.log(`      Payload: ${result.payload.substring(0, 80)}...`);
    }
    if (result.evidence) {
      console.log(`      Evidence: ${JSON.stringify(result.evidence).substring(0, 80)}...`);
    }
  });
  
  console.log('\n✅ Phase 3 test complete!');
}

testPhase3().catch(err => {
  console.error('❌ Test failed:', err);
  console.error(err.stack);
  process.exit(1);
});
