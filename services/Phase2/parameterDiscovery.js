// Phase 2: Parameter Discovery - Extract and classify parameters
const axios = require('axios');
const cheerio = require('cheerio');

class ParameterDiscovery {
  /**
   * Discover parameters from endpoint
   */
  static async discoverParameters(url, method = 'GET') {
    const parameters = [];

    try {
      // Extract from URL query string
      const urlParams = this._extractURLParameters(url);
      parameters.push(...urlParams);

      // Extract from HTML forms
      if (method === 'GET' || method === 'POST') {
        const formParams = await this._extractFormParameters(url);
        parameters.push(...formParams);
      }

      // Extract from API responses
      const apiParams = await this._extractAPIParameters(url);
      parameters.push(...apiParams);

      // Classify parameters
      const classified = this._classifyParameters(parameters);

      return {
        success: true,
        url,
        parameters: classified
      };
    } catch (error) {
      console.error('Parameter discovery error:', error);
      return {
        success: false,
        error: error.message,
        parameters: []
      };
    }
  }

  /**
   * Extract URL query parameters
   */
  static _extractURLParameters(url) {
    const parameters = [];
    
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((value, key) => {
        parameters.push({
          name: key,
          value: value,
          location: 'query',
          type: 'unknown'
        });
      });
    } catch (error) {
      console.error('Error parsing URL:', error);
    }

    return parameters;
  }

  /**
   * Extract form parameters
   */
  static async _extractFormParameters(url) {
    const parameters = [];

    try {
      const response = await axios.get(url, {
        timeout: 30000, // Increased to 30 seconds
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        validateStatus: () => true
      });

      const $ = cheerio.load(response.data);

      $('form').each((_, form) => {
        $(form).find('input, textarea, select').each((_, input) => {
          const $input = $(input);
          parameters.push({
            name: $input.attr('name'),
            type: $input.attr('type') || 'text',
            value: $input.attr('value') || '',
            location: 'form',
            required: $input.attr('required') ? true : false
          });
        });
      });
    } catch (error) {
      console.error('Error extracting form parameters:', error);
    }

    return parameters;
  }

  /**
   * Extract API response parameters
   */
  static async _extractAPIParameters(url) {
    const parameters = [];

    try {
      const response = await axios.get(url, {
        timeout: 30000, // Increased to 30 seconds
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        validateStatus: () => true
      });

      if (typeof response.data === 'object') {
        const keys = this._extractJSONKeys(response.data);
        keys.forEach(key => {
          parameters.push({
            name: key,
            location: 'response',
            type: 'json_field'
          });
        });
      }
    } catch (error) {
      console.error('Error extracting API parameters:', error);
    }

    return parameters;
  }

  /**
   * Extract all keys from nested JSON
   */
  static _extractJSONKeys(obj, prefix = '') {
    let keys = [];

    if (typeof obj !== 'object' || obj === null) {
      return keys;
    }

    Object.keys(obj).forEach(key => {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      keys.push(fullKey);

      if (typeof obj[key] === 'object' && obj[key] !== null) {
        keys = keys.concat(this._extractJSONKeys(obj[key], fullKey));
      }
    });

    return keys;
  }

  /**
   * Classify parameters by sensitivity
   */
  static _classifyParameters(parameters) {
    return parameters.map(param => {
      const classified = { ...param };

      // Classify by name patterns (with safety check)
      if (!param.name || typeof param.name !== 'string') {
        return classified; // Skip invalid parameters
      }
      
      const name = param.name.toLowerCase();

      if (name.match(/password|pwd|pass/)) {
        classified.classification = 'sensitive_auth';
        classified.sensitivity = 'critical';
        classified.riskLevel = 'critical';
        classified.recommendedTests = ['SQLi', 'Authentication Bypass'];
      } else if (name.match(/email|user|username|login/)) {
        classified.classification = 'user_identifier';
        classified.sensitivity = 'high';
        classified.riskLevel = 'high';
        classified.recommendedTests = ['SQLi', 'XSS', 'IDOR'];
      } else if (name.match(/token|api[_-]?key|secret|auth/)) {
        classified.classification = 'authentication';
        classified.sensitivity = 'critical';
        classified.riskLevel = 'critical';
        classified.recommendedTests = ['Authentication Bypass', 'IDOR'];
      } else if (name.match(/url|uri|path|file|directory/)) {
        classified.classification = 'path_like';
        classified.sensitivity = 'high';
        classified.riskLevel = 'high';
        classified.recommendedTests = ['Path Traversal', 'LFI', 'SSRF'];
      } else if (name.match(/id|_id|userid|user_id/)) {
        classified.classification = 'identifier';
        classified.sensitivity = 'medium';
        classified.riskLevel = 'medium';
        classified.recommendedTests = ['SQLi', 'IDOR'];
      } else if (name.match(/search|query|q/)) {
        classified.classification = 'search';
        classified.sensitivity = 'medium';
        classified.riskLevel = 'medium';
        classified.recommendedTests = ['XSS', 'SQLi'];
      } else if (name.match(/filter|sort|order/)) {
        classified.classification = 'filter';
        classified.sensitivity = 'low';
        classified.riskLevel = 'low';
        classified.recommendedTests = ['SQLi'];
      } else if (name.match(/callback|redirect|return/)) {
        classified.classification = 'redirect_like';
        classified.sensitivity = 'high';
        classified.riskLevel = 'high';
        classified.recommendedTests = ['Open Redirect', 'SSRF'];
      } else {
        classified.classification = 'generic';
        classified.sensitivity = 'low';
        classified.riskLevel = 'low';
        classified.recommendedTests = ['XSS', 'SQLi'];
      }

      return classified;
    });
  }

  /**
   * Get injectable parameters — all non-response params
   * (includes auth params so SQLi agent can test login bypass)
   */
  static getInjectableParameters(parameters) {
    return parameters.filter(param => 
      param.name &&
      typeof param.name === 'string' &&
      param.location !== 'response'
    );
  }

  /**
   * Batch discover parameters
   */
  static async discoverParametersBatch(endpoints) {
    const results = [];
    for (const endpoint of endpoints) {
      const result = await this.discoverParameters(endpoint.url, endpoint.method);
      results.push({
        endpoint: endpoint.url,
        ...result
      });
    }
    return results;
  }
}

module.exports = ParameterDiscovery;
