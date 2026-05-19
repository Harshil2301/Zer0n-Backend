// Test Information Disclosure Detection
const AdvancedExploitationService = require('./services/Phase3/advancedExploitationService');

async function testInfoDisclosure() {
  console.log('🧪 Testing Information Disclosure Detection\n');
  console.log('=' .repeat(70));
  
  // Test endpoints that might have info disclosure
  const testCases = [
    {
      endpoint: { 
        url: 'http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg',
        method: 'GET' 
      },
      parameter: { 
        name: 'file', 
        classification: 'path',
        sensitivity: 'high'
      },
      description: 'Path traversal potential (file parameter)'
    },
    {
      endpoint: { 
        url: 'http://testphp.vulnweb.com/product.php?pic=1',
        method: 'GET' 
      },
      parameter: { 
        name: 'pic', 
        classification: 'id',
        sensitivity: 'medium'
      },
      description: 'File inclusion potential (pic parameter)'
    },
    {
      endpoint: { 
        url: 'http://testphp.vulnweb.com/listproducts.php?cat=1',
        method: 'GET' 
      },
      parameter: { 
        name: 'cat', 
        classification: 'id',
        sensitivity: 'medium'
      },
      description: 'SQL error disclosure potential'
    }
  ];

  let totalFound = 0;
  
  for (const testCase of testCases) {
    console.log(`\n📋 Test Case: ${testCase.description}`);
    console.log(`   Endpoint: ${testCase.endpoint.url}`);
    console.log(`   Parameter: ${testCase.parameter.name}\n`);
    
    try {
      const results = await AdvancedExploitationService.testInfoDisclosureOnly(
        testCase.endpoint,
        testCase.parameter
      );
      
      if (results.length > 0) {
        console.log(`   ✅ Found ${results.length} information disclosure(s):`);
        results.forEach((result, idx) => {
          console.log(`\n      [${idx + 1}] Type: ${result.subType || result.type}`);
          console.log(`          Confidence: ${result.confidence}%`);
          console.log(`          Payload: ${result.payloadUsed}`);
          console.log(`          Evidence: ${result.evidence[0]}`);
        });
        totalFound += results.length;
      } else {
        console.log(`   ⚪ No information disclosure detected`);
      }
      
    } catch (error) {
      console.error(`   ❌ Error: ${error.message}`);
    }
    
    console.log('\n' + '-'.repeat(70));
  }
  
  console.log(`\n✅ Test Complete: ${totalFound} Information Disclosure vulnerabilities found`);
  console.log('=' .repeat(70));
}

// Run the test
testInfoDisclosure().catch(console.error);
