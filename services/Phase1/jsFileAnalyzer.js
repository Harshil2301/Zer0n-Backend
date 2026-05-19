// Phase 1: JavaScript File Analyzer - Extract API endpoints from JS files
const axios = require('axios');
const cheerio = require('cheerio');

class JSFileAnalyzer {
  /**
   * Find and analyze JavaScript files
   */
  static async analyzeJSFiles(baseUrl) {
    console.log(`    📜 Analyzing JavaScript files...`);
    const endpoints = [];
    const apiEndpoints = new Set();

    try {
      // Get main page
      const response = await axios.get(baseUrl, {
        timeout: 30000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        validateStatus: () => true
      });

      const $ = cheerio.load(response.data);
      const jsFiles = [];

      // Extract all JS file URLs
      $('script[src]').each((_, el) => {
        const src = $(el).attr('src');
        if (src) {
          try {
            const jsUrl = new URL(src, baseUrl).href;
            jsFiles.push(jsUrl);
          } catch (e) {
            // Invalid URL
          }
        }
      });

      console.log(`       ✓ Found ${jsFiles.length} JavaScript files`);

      // Analyze each JS file
      for (const jsUrl of jsFiles.slice(0, 10)) {
        try {
          const jsResponse = await axios.get(jsUrl, {
            timeout: 15000,
            headers: { 'User-Agent': 'Mozilla/5.0' },
            validateStatus: () => true
          });

          const jsContent = jsResponse.data;
          const extractedEndpoints = this._extractEndpointsFromJS(jsContent, baseUrl);
          
          extractedEndpoints.forEach(ep => apiEndpoints.add(ep));
        } catch (error) {
          // Skip if JS file can't be fetched
        }
      }

      console.log(`       ✓ Extracted ${apiEndpoints.size} API endpoints from JS`);

      return Array.from(apiEndpoints).map(url => ({
        url,
        method: 'GET',
        type: 'js_extracted'
      }));
    } catch (error) {
      console.log(`       ⚠ JS analysis failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Extract API endpoints from JavaScript content
   */
  static _extractEndpointsFromJS(jsContent, baseUrl) {
    const endpoints = new Set();
    const urlObj = new URL(baseUrl);

    // Pattern 1: '/api/...' or '/v1/...'
    const apiPattern = /['"`](\/(?:api|v\d+|rest|graphql)\/[^'"`\s)]+)['"`]/g;
    let match;
    while ((match = apiPattern.exec(jsContent)) !== null) {
      try {
        const endpoint = new URL(match[1], baseUrl).href;
        endpoints.add(endpoint);
      } catch (e) {}
    }

    // Pattern 2: Full URLs with same domain
    const fullUrlPattern = /['"`](https?:\/\/[^'"`\s]+)['"`]/g;
    while ((match = fullUrlPattern.exec(jsContent)) !== null) {
      try {
        const url = new URL(match[1]);
        if (url.hostname === urlObj.hostname) {
          endpoints.add(match[1]);
        }
      } catch (e) {}
    }

    // Pattern 3: Relative paths like './path' or '../path'
    const relativePattern = /['"`](\.\/?[a-zA-Z0-9_\-\/]+\.[a-z]{2,4})['"`]/g;
    while ((match = relativePattern.exec(jsContent)) !== null) {
      try {
        const endpoint = new URL(match[1], baseUrl).href;
        endpoints.add(endpoint);
      } catch (e) {}
    }

    // Pattern 4: Query parameters
    const queryPattern = /['"`]([^'"`\s]+\?[a-zA-Z0-9_]+=)['"`]/g;
    while ((match = queryPattern.exec(jsContent)) !== null) {
      try {
        const endpoint = new URL(match[1], baseUrl).href;
        endpoints.add(endpoint);
      } catch (e) {}
    }

    return Array.from(endpoints);
  }
}

module.exports = JSFileAnalyzer;
