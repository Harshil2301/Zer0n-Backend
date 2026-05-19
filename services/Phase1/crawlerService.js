// Phase 1: Crawler Service - Enumerate URLs, APIs, endpoints
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

class CrawlerService {
  constructor() {
    this.visited = new Set();
    this.endpoints = [];
    this.maxDepth = 3;
    this.maxPages = 1000;
    // High-cardinality params that cause infinite spider-traps
    this._skipParams = new Set(['id','token','session','auth','csrf','page','offset','cursor','ts','timestamp','_','rand','v','ver']);
  }

  /**
   * Normalize a URL for dedup purposes by stripping high-cardinality query params.
   * This prevents dynamic pages like ?id=1, ?id=2 from being treated as unique.
   */
  _normalizeUrl(urlStr) {
    try {
      const u = new URL(urlStr);
      const kept = [];
      for (const [k, val] of u.searchParams.entries()) {
        if (!this._skipParams.has(k.toLowerCase())) {
          kept.push(`${k}=${val}`);
        }
      }
      return `${u.hostname}${u.pathname}${kept.length ? '?' + kept.join('&') : ''}`;
    } catch {
      return urlStr;
    }
  }

  /**
   * Start crawling a target
   */
  async crawl(startUrl, options = {}) {
    this.maxDepth = options.maxDepth || 3;
    this.maxPages = options.maxPages || 1000;
    this.sessionCookie = options.sessionCookie || '';
    this.visited.clear();
    this.endpoints = [];

    try {
      await this._crawlRecursive(startUrl, 0);
      return {
        success: true,
        endpointCount: this.endpoints.length,
        endpoints: this.endpoints
      };
    } catch (error) {
      console.error('Crawling error:', error);
      return {
        success: false,
        error: error.message,
        endpoints: this.endpoints
      };
    }
  }

  /**
   * Recursive crawling function
   */
  async _crawlRecursive(url, depth) {
    if (depth > this.maxDepth || this.visited.size >= this.maxPages) {
      return;
    }

    const normalizedKey = this._normalizeUrl(url);
    if (this.visited.has(normalizedKey)) {
      return;
    }

    this.visited.add(normalizedKey);

    try {
      const response = await axios.get(url, {
        timeout: 30000, // Increased to 30 seconds
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          ...(this.sessionCookie ? { 'Cookie': this.sessionCookie } : {})
        },
        maxRedirects: 5,
        validateStatus: () => true // Accept any status code
      });

      const $ = cheerio.load(response.data);
      const links = new Set();

      // Add the current page as an endpoint if it has query parameters
      const urlObj = new URL(url);
      if (urlObj.search) {
        this.endpoints.push({
          url: url,
          method: 'GET',
          type: 'discovered',
          source: 'crawler'
        });
      }

      // Extract all links
      $('a[href]').each((_, element) => {
        const href = $(element).attr('href');
        if (href) {
          try {
            const absoluteUrl = new URL(href, url).href;
            const targetHost = new URL(url).hostname;
            const linkHost = new URL(absoluteUrl).hostname;

            // Only crawl same domain
            if (linkHost === targetHost && !this.visited.has(absoluteUrl)) {
              links.add(absoluteUrl);
              
              // Add links with query parameters as endpoints immediately
              const linkUrlObj = new URL(absoluteUrl);
              if (linkUrlObj.search) {
                this.endpoints.push({
                  url: absoluteUrl,
                  method: 'GET',
                  type: 'discovered',
                  source: 'crawler'
                });
              }
            }
          } catch (e) {
            // Invalid URL
          }
        }
      });

      // Extract forms and other endpoints
      this._extractEndpoints($, url);

      // Crawl child links
      for (const link of links) {
        await this._crawlRecursive(link, depth + 1);
      }
    } catch (error) {
      console.error(`Error crawling ${url}:`, error.message);
    }
  }

  /**
   * Extract endpoints, forms, and API calls
   */
  _extractEndpoints($, baseUrl) {
    const baseUrlObj = new URL(baseUrl);

    // Extract forms
    $('form').each((_, form) => {
      const action = $(form).attr('action');
      const method = $(form).attr('method') || 'GET';
      let endpoint = action;
      
      // Handle relative URLs
      if (action) {
        try {
          endpoint = new URL(action, baseUrl).href;
        } catch (e) {
          endpoint = baseUrl; // Use base URL if action is invalid
        }
      } else {
        endpoint = baseUrl; // Form submits to same page
      }

      // Extract input fields
      const inputs = [];
      $(form).find('input, textarea, select').each((_, input) => {
        const name = $(input).attr('name');
        const type = $(input).attr('type') || 'text';
        if (name) {
          inputs.push({ name, type });
        }
      });

      this.endpoints.push({
        url: endpoint,
        method: method.toUpperCase(),
        type: 'form',
        source: 'crawler',
        inputs: inputs
      });
    });

    // Extract API calls and scripts
    $('script').each((_, script) => {
      const content = $(script).html();
      if (content) {
        this._extractAPIFromScript(content, baseUrlObj);
      }
    });

    // Extract data attributes and onclick handlers
    $('[onclick], [data-url], [data-api]').each((_, element) => {
      const onclick = $(element).attr('onclick');
      const dataUrl = $(element).attr('data-url');
      const dataApi = $(element).attr('data-api');

      if (onclick) this._extractFromString(onclick, baseUrlObj);
      if (dataUrl) {
        try {
          const fullUrl = new URL(dataUrl, baseUrl).href;
          this.endpoints.push({ 
            url: fullUrl, 
            method: 'GET',
            type: 'data-attribute',
            source: 'crawler'
          });
        } catch (e) {
          // Invalid URL
        }
      }
      if (dataApi) {
        try {
          const fullUrl = new URL(dataApi, baseUrl).href;
          this.endpoints.push({ 
            url: fullUrl, 
            method: 'GET',
            type: 'api',
            source: 'crawler'
          });
        } catch (e) {
          // Invalid URL
        }
      }
    });
  }

  /**
   * Extract API endpoints from JavaScript
   */
  _extractAPIFromScript(content, baseUrlObj) {
    const hostname = baseUrlObj.hostname;
    const protocol = baseUrlObj.protocol;
    
    // Pattern: /api/endpoint, /v1/users, etc.
    const apiPattern = /['"](\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*)['"]/g;
    let match;

    while ((match = apiPattern.exec(content)) !== null) {
      const endpoint = match[1];
      if (endpoint.startsWith('/') && endpoint.length > 1) {
        this.endpoints.push({
          url: `${protocol}//${hostname}${endpoint}`,
          method: 'GET',
          type: 'api',
          source: 'script'
        });
      }
    }

    // Pattern: https://domain/api/...
    const fullUrlPattern = /https?:\/\/[a-zA-Z0-9.-]+[a-zA-Z0-9.-]*\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*/g;
    while ((match = fullUrlPattern.exec(content)) !== null) {
      const url = match[0];
      try {
        const urlObj = new URL(url);
        if (urlObj.hostname === hostname || urlObj.hostname.endsWith(`.${hostname}`)) {
          this.endpoints.push({
            url: url,
            method: 'GET',
            type: 'api',
            source: 'script'
          });
        }
      } catch (e) {
        // Invalid URL
      }
    }
  }

  /**
   * Extract URLs from JavaScript string
   */
  _extractFromString(str, baseUrlObj) {
    const hostname = baseUrlObj.hostname;
    const protocol = baseUrlObj.protocol;
    
    const urlPattern = /['"](\/[^'"]+)['"]/g;
    let match;

    while ((match = urlPattern.exec(str)) !== null) {
      const endpoint = match[1];
      if (endpoint.startsWith('/')) {
        this.endpoints.push({
          url: `${protocol}//${hostname}${endpoint}`,
          method: 'GET',
          type: 'extracted',
          source: 'onclick'
        });
      }
    }
  }

  /**
   * Remove duplicates and normalize endpoints
   */
  static deduplicateEndpoints(endpoints) {
    const unique = new Map();

    endpoints.forEach(endpoint => {
      const key = `${endpoint.method || 'GET'}:${endpoint.url}`;
      if (!unique.has(key)) {
        unique.set(key, endpoint);
      }
    });

    return Array.from(unique.values());
  }
}

module.exports = CrawlerService;
