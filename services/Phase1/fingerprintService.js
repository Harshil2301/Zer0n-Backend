// Phase 1: Fingerprint Service - Detect frameworks, versions, technologies
const axios = require('axios');
const cheerio = require('cheerio');

class FingerprintService {
  /**
   * Fingerprint a target domain
   */
  static async fingerprint(url) {
    try {
      const response = await axios.get(url, {
        timeout: 30000, // Increased to 30 seconds
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        validateStatus: () => true // Accept any status code
      });

      const technologies = [];
      const headers = response.headers;
      const html = response.data;

      // Detect from headers
      this._detectFromHeaders(headers, technologies);

      // Detect from HTML
      this._detectFromHTML(html, technologies);

      // Detect from status codes and behavior
      this._detectFromBehavior(response, technologies);

      return {
        success: true,
        url,
        technologies: [...new Set(technologies)],
        headers: this._sanitizeHeaders(headers)
      };
    } catch (error) {
      console.error('Fingerprinting error:', error);
      return {
        success: false,
        error: error.message,
        technologies: []
      };
    }
  }

  /**
   * Detect technologies from HTTP headers
   */
  static _detectFromHeaders(headers, technologies) {
    const signatures = {
      'server': ['Apache', 'Nginx', 'IIS', 'Tomcat', 'Node.js', 'Kestrel'],
      'x-powered-by': ['PHP', 'ASP.NET', 'Express', 'Flask', 'Django'],
      'x-aspnet-version': ['ASP.NET'],
      'x-frame-options': ['Security'],
      'content-security-policy': ['Security'],
      'x-xss-protection': ['Security']
    };

    Object.entries(signatures).forEach(([header, techs]) => {
      const value = headers[header.toLowerCase()];
      if (value) {
        techs.forEach(tech => {
          if (value.toLowerCase().includes(tech.toLowerCase())) {
            technologies.push(tech);
          }
        });
      }
    });

    // Detect specific versions
    if (headers.server) {
      const serverHeader = headers.server;
      const versionMatch = serverHeader.match(/(\d+\.\d+[\.\d]*)/g);
      if (versionMatch) {
        technologies.push(`Version: ${versionMatch[0]}`);
      }
    }
  }

  /**
   * Detect technologies from HTML content
   */
  static _detectFromHTML(html, technologies) {
    const $ = cheerio.load(html);

    // Meta tags and generators
    const generator = $('meta[name="generator"]').attr('content');
    if (generator) {
      technologies.push(generator);
    }

    // HTML comments often reveal tech stack
    const htmlStr = $.html();
    const commentMatch = htmlStr.match(/<!--[\s\S]*?-->/g);
    if (commentMatch) {
      commentMatch.forEach(comment => {
        if (comment.toLowerCase().includes('wordpress')) technologies.push('WordPress');
        if (comment.toLowerCase().includes('joomla')) technologies.push('Joomla');
        if (comment.toLowerCase().includes('drupal')) technologies.push('Drupal');
      });
    }

    // Script sources
    $('script[src]').each((_, el) => {
      const src = $(el).attr('src');
      if (src) {
        if (src.includes('jquery')) technologies.push('jQuery');
        if (src.includes('angular')) technologies.push('Angular');
        if (src.includes('react')) technologies.push('React');
        if (src.includes('vue')) technologies.push('Vue.js');
        if (src.includes('bootstrap')) technologies.push('Bootstrap');
      }
    });

    // Specific framework indicators
    if ($('link[href*="bootstrap"]').length > 0) technologies.push('Bootstrap');
    if ($('[ng-app]').length > 0) technologies.push('Angular');
    if ($('[v-app]').length > 0) technologies.push('Vue.js');
    if ($('[data-react]').length > 0) technologies.push('React');

    // WordPress indicators
    if ($('link[href*="wp-content"]').length > 0) technologies.push('WordPress');

    // Joomla indicators
    if ($('meta[name="generator"][content*="Joomla"]').length > 0) technologies.push('Joomla');
  }

  /**
   * Detect technologies from response behavior
   */
  static _detectFromBehavior(response, technologies) {
    const status = response.status;

    // Common redirects and behaviors
    if (response.config.url.includes('/wp-admin')) technologies.push('WordPress');
    if (response.config.url.includes('/administrator')) technologies.push('Joomla');
    if (response.config.url.includes('/admin')) technologies.push('CMS');
  }

  /**
   * Sanitize headers for output
   */
  static _sanitizeHeaders(headers) {
    const sensitive = ['authorization', 'cookie', 'x-api-key', 'x-access-token'];
    const sanitized = {};

    Object.entries(headers).forEach(([key, value]) => {
      if (!sensitive.some(s => key.toLowerCase().includes(s))) {
        sanitized[key] = value;
      }
    });

    return sanitized;
  }

  /**
   * Batch fingerprint multiple URLs
   */
  static async fingerprintBatch(urls) {
    const results = [];
    for (const url of urls) {
      const result = await this.fingerprint(url);
      results.push(result);
    }
    return results;
  }

  /**
   * Identify technology stack from multiple endpoints
   */
  static aggregateTechStack(fingerprintResults) {
    const techStack = {};

    fingerprintResults.forEach(result => {
      if (result.technologies) {
        result.technologies.forEach(tech => {
          if (!techStack[tech]) {
            techStack[tech] = 0;
          }
          techStack[tech]++;
        });
      }
    });

    // Sort by frequency
    return Object.entries(techStack)
      .sort(([, a], [, b]) => b - a)
      .map(([tech, count]) => ({ technology: tech, frequency: count }));
  }
}

module.exports = FingerprintService;
