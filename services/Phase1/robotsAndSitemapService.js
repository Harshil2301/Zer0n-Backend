// Phase 1: Robots.txt & Sitemap.xml Parser
const axios = require('axios');
const cheerio = require('cheerio');

class RobotsAndSitemapService {
  /**
   * Parse robots.txt for disallowed paths (often interesting!)
   */
  static async parseRobotsTxt(baseUrl) {
    console.log(`    🤖 Parsing robots.txt...`);
    const paths = [];

    try {
      const robotsUrl = new URL('/robots.txt', baseUrl).href;
      const response = await axios.get(robotsUrl, {
        timeout: 3000,
        headers: { 'User-Agent': 'Mozilla/5.0' },
        validateStatus: () => true
      });

      if (response.status === 200 && response.data) {
        const lines = response.data.split('\n');
        
        lines.forEach(line => {
          // Disallow: /admin/ (these are GOLD for bug bounty!)
          if (line.toLowerCase().includes('disallow:')) {
            const path = line.split(':')[1]?.trim();
            if (path && path !== '/') {
              try {
                const fullUrl = new URL(path, baseUrl).href;
                paths.push(fullUrl);
              } catch (e) {}
            }
          }

          // Sitemap reference
          if (line.toLowerCase().includes('sitemap:')) {
            const sitemapUrl = line.split(':').slice(1).join(':').trim();
            if (sitemapUrl) {
              paths.push(sitemapUrl);
            }
          }
        });

        console.log(`       ✓ Found ${paths.length} paths in robots.txt`);
      }
    } catch (error) {
      console.log(`       ⚠ No robots.txt found`);
    }

    return paths;
  }

  /**
   * Parse sitemap.xml
   */
  static async parseSitemap(baseUrl) {
    console.log(`    🗺️  Parsing sitemap.xml...`);
    const urls = [];

    try {
      const sitemapUrl = new URL('/sitemap.xml', baseUrl).href;
      const response = await axios.get(sitemapUrl, {
        timeout: 3000,
        headers: { 'User-Agent': 'Mozilla/5.0' },
        validateStatus: () => true
      });

      if (response.status === 200 && response.data) {
        const $ = cheerio.load(response.data, { xmlMode: true });
        
        $('url loc').each((_, el) => {
          const url = $(el).text();
          if (url) {
            urls.push(url);
          }
        });

        // Handle sitemap index
        $('sitemap loc').each((_, el) => {
          const url = $(el).text();
          if (url) {
            urls.push(url);
          }
        });

        console.log(`       ✓ Found ${urls.length} URLs in sitemap`);
      }
    } catch (error) {
      console.log(`       ⚠ No sitemap.xml found`);
    }

    return urls;
  }
}

module.exports = RobotsAndSitemapService;
