// Test script for CrawlerService
const CrawlerService = require('./services/Phase1/crawlerService');

async function testCrawler() {
  console.log('🧪 Testing CrawlerService...\n');
  
  const crawler = new CrawlerService();
  const target = 'http://testphp.vulnweb.com';
  
  console.log(`📍 Target: ${target}`);
  console.log(`⚙️  Options: maxDepth=3, maxPages=100\n`);
  
  console.log('🕷️  Starting crawl...\n');
  const result = await crawler.crawl(target, {
    maxDepth: 3,
    maxPages: 100
  });
  
  console.log('\n📊 Crawl Results:');
  console.log(`   Success: ${result.success}`);
  console.log(`   Total Endpoints: ${result.endpoints.length}`);
  console.log(`   Visited Pages: ${crawler.visited.size}\n`);
  
  // Group by type
  const byType = {};
  result.endpoints.forEach(ep => {
    const type = ep.type || 'unknown';
    if (!byType[type]) byType[type] = [];
    byType[type].push(ep);
  });
  
  console.log('📋 Endpoints by Type:');
  Object.keys(byType).forEach(type => {
    console.log(`   ${type}: ${byType[type].length}`);
  });
  
  console.log('\n🔍 Sample Endpoints (first 10):');
  result.endpoints.slice(0, 10).forEach((ep, i) => {
    console.log(`   ${i+1}. [${ep.method}] ${ep.url}`);
    console.log(`      Type: ${ep.type}, Source: ${ep.source || 'N/A'}`);
  });
  
  // Check for endpoints with parameters
  const withParams = result.endpoints.filter(ep => {
    try {
      const url = new URL(ep.url);
      return url.search !== '';
    } catch (e) {
      return false;
    }
  });
  
  console.log(`\n✨ Endpoints with Query Parameters: ${withParams.length}`);
  withParams.slice(0, 5).forEach((ep, i) => {
    console.log(`   ${i+1}. ${ep.url}`);
  });
  
  // Test deduplication
  const unique = CrawlerService.deduplicateEndpoints(result.endpoints);
  console.log(`\n🔄 After Deduplication: ${unique.length} unique endpoints`);
}

testCrawler().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
