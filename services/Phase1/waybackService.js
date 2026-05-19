// Phase 1: Wayback Machine Integration - Find historical URLs
const axios = require('axios');

class WaybackService {
  /**
   * Get URLs from Wayback Machine (archive.org)
   */
  static async getHistoricalUrls(domain) {
    console.log(`    🕰️  Querying Wayback Machine for ${domain}...`);
    const urls = [];

    try {
      // Wayback Machine CDX API
      const response = await axios.get(
        `http://web.archive.org/cdx/search/cdx`,
        {
          params: {
            url: `${domain}/*`,
            output: 'json',
            fl: 'original',
            collapse: 'urlkey',
            limit: 1000
          },
          timeout: 3000
        }
      );

      if (Array.isArray(response.data)) {
        // Skip header row
        const data = response.data.slice(1);
        data.forEach(row => {
          if (row[0]) {
            urls.push(row[0]);
          }
        });
      }

      console.log(`       ✓ Found ${urls.length} historical URLs`);
      return urls;
    } catch (error) {
      console.log(`       ⚠ Wayback Machine unavailable: ${error.message}`);
      return [];
    }
  }

  /**
   * Get unique paths from URLs
   */
  static extractPaths(urls) {
    const paths = new Set();
    
    urls.forEach(url => {
      try {
        const urlObj = new URL(url);
        if (urlObj.pathname !== '/') {
          paths.add(urlObj.pathname + urlObj.search);
        }
      } catch (e) {
        // Invalid URL, skip
      }
    });

    return Array.from(paths);
  }
}

module.exports = WaybackService;
