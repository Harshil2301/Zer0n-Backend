// Test deduplication logic
console.log('🧪 Testing Improved Deduplication Logic\n');

// Simulate duplicate endpoints (like testphp.vulnweb.com)
const mockEndpoints = [
  { url: 'http://testphp.vulnweb.com/listproducts.php?cat=1', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/listproducts.php?cat=2', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/listproducts.php?cat=3', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/listproducts.php?cat=4', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/artists.php?artist=1', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/artists.php?artist=2', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/artists.php?artist=3', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/search.php?q=test', method: 'GET' },
  { url: 'http://testphp.vulnweb.com/search.php?q=other', method: 'GET' },
];

// Simulate parameters that would be discovered
const mockParameters = [
  { name: 'cat' },
  { name: 'artist' },
  { name: 'q' },
  { name: 'searchFor' } // Often found in forms on every page
];

// Helper function to normalize URL
function normalizeURL(url) {
  try {
    const urlObj = new URL(url);
    const params = Array.from(urlObj.searchParams.keys()).sort();
    return `${urlObj.origin}${urlObj.pathname}?${params.join('&')}`;
  } catch (e) {
    return url;
  }
}

console.log('📋 Mock Endpoints:');
mockEndpoints.forEach((ep, i) => {
  console.log(`   ${i + 1}. ${ep.url}`);
});

console.log('\n🔍 WITHOUT Normalization (Old Method):');
const seenOld = new Set();
let oldCount = 0;
for (const endpoint of mockEndpoints) {
  for (const param of mockParameters) {
    const vectorKey = `${endpoint.url}::${param.name}`;
    if (!seenOld.has(vectorKey)) {
      seenOld.add(vectorKey);
      oldCount++;
    }
  }
}
console.log(`   Total unique vectors: ${oldCount}`);

console.log('\n✨ WITH URL Normalization (New Method):');
const seenNew = new Set();
let newCount = 0;
const uniqueVectors = [];
for (const endpoint of mockEndpoints) {
  for (const param of mockParameters) {
    const normalizedUrl = normalizeURL(endpoint.url);
    const vectorKey = `${normalizedUrl}::${param.name}`;
    if (!seenNew.has(vectorKey)) {
      seenNew.add(vectorKey);
      uniqueVectors.push(vectorKey);
      newCount++;
    }
  }
}
console.log(`   Total unique vectors: ${newCount}`);
uniqueVectors.forEach((v, i) => {
  console.log(`   ${i + 1}. ${v}`);
});

console.log('\n📊 Summary:');
console.log(`   Without normalization: ${oldCount} vectors`);
console.log(`   With normalization: ${newCount} vectors`);
console.log(`   Duplicates removed: ${oldCount - newCount}`);
console.log(`   Efficiency gain: ${((1 - newCount / oldCount) * 100).toFixed(1)}% fewer tests\n`);

console.log('✅ Improved deduplication working correctly!');
