// Test Phase 2: Parameter Discovery
const ParameterDiscovery = require('./services/Phase2/parameterDiscovery');

async function testPhase2() {
  console.log('🧪 Testing Phase 2: Parameter Discovery\n');
  
  // Mock endpoints from crawler
  const mockEndpoints = [
    { url: 'http://testphp.vulnweb.com/listproducts.php?cat=1', method: 'GET', type: 'discovered' },
    { url: 'http://testphp.vulnweb.com/artists.php?artist=2', method: 'GET', type: 'discovered' },
    { url: 'http://testphp.vulnweb.com/search.php?test=query', method: 'POST', type: 'form' },
    { url: 'http://testphp.vulnweb.com/comment.php?aid=1', method: 'GET', type: 'discovered' },
    { url: 'http://testphp.vulnweb.com/showimage.php?file=test.jpg', method: 'GET', type: 'discovered' }
  ];
  
  console.log(`📋 Testing with ${mockEndpoints.length} endpoints:\n`);
  mockEndpoints.forEach((ep, i) => {
    console.log(`   ${i+1}. [${ep.method}] ${ep.url}`);
  });
  
  console.log('\n🔍 Discovering parameters...\n');
  
  const allVectors = [];
  for (const endpoint of mockEndpoints) {
    console.log(`   Analyzing: ${endpoint.url}`);
    const paramResult = await ParameterDiscovery.discoverParameters(endpoint.url, endpoint.method);
    
    if (paramResult.success && paramResult.parameters) {
      console.log(`      Found ${paramResult.parameters.length} parameters:`);
      
      paramResult.parameters.forEach(param => {
        console.log(`         • ${param.name} (${param.source}, risk: ${param.riskLevel})`);
        allVectors.push({ endpoint, parameter: param });
      });
    } else {
      console.log(`      ⚠ No parameters found`);
    }
  }
  
  console.log(`\n✅ Total attack vectors: ${allVectors.length}`);
  
  // Show sample attack vectors
  console.log(`\n🎯 Sample Attack Vectors (first 5):`);
  allVectors.slice(0, 5).forEach((v, i) => {
    console.log(`   ${i+1}. ${v.endpoint.url}`);
    console.log(`      Parameter: ${v.parameter.name}`);
    console.log(`      Risk: ${v.parameter.riskLevel}`);
    console.log(`      Recommended Tests: ${v.parameter.recommendedTests.join(', ')}`);
  });
}

testPhase2().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
