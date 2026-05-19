// Phase 3: Response Analyzer - Parse responses for vulnerability indicators
class ResponseAnalyzer {
  /**
   * Analyze response for vulnerability indicators
   */
  static analyzeResponse(response, payload, vulnType) {
    const analysis = {
      vulnerable: false,
      indicators: [],
      confidence: 0,
      details: {}
    };

    switch (vulnType) {
      case 'SQLi':
        analysis.vulnerable = this._analyzeSQLiResponse(response, analysis);
        break;
      case 'XSS':
        analysis.vulnerable = this._analyzeXSSResponse(response, payload, analysis);
        break;
      case 'SSRF':
        analysis.vulnerable = this._analyzeSSRFResponse(response, analysis);
        break;
      case 'PathTraversal':
        analysis.vulnerable = this._analyzePathTraversalResponse(response, analysis);
        break;
      case 'RCE':
        analysis.vulnerable = this._analyzeRCEResponse(response, analysis);
        break;
      case 'XXE':
        analysis.vulnerable = this._analyzeXXEResponse(response, analysis);
        break;
      case 'LFI':
        analysis.vulnerable = this._analyzeLFIResponse(response, analysis);
        break;
      default:
        analysis.vulnerable = this._analyzeGenericResponse(response, analysis);
    }

    // Calculate confidence based on indicators
    analysis.confidence = Math.min(analysis.indicators.length * 25, 100);

    return analysis;
  }

  /**
   * Analyze SQLi response
   */
  static _analyzeSQLiResponse(response, analysis) {
    const data = String(response.data || '');
    const dataLower = data.toLowerCase();
    
    // SQL Error Patterns (REAL bug bounty hunter patterns)
    const sqlErrors = [
      // MySQL errors
      'you have an error in your sql syntax',
      'warning: mysql',
      'unclosed quotation mark after the character string',
      'quoted string not properly terminated',
      'sql syntax',
      'mysql_fetch',
      'mysql_num_rows',
      'mysqli_',
      'mysql server version',
      
      // PostgreSQL
      'pg_query',
      'pg_exec',
      'postgresql',
      'warning: pg_',
      'valid postgresql result',
      
      // MSSQL
      'driver.*.sql server',
      'ole db.* sql server',
      'unclosed quotation mark before the character string',
      '\\[sql server\\]',
      '\\[microsoft\\]\\[odbc sql',
      
      // Oracle
      'ora-[0-9]{4,5}',
      'oracle error',
      'oracle.*driver',
      'warning.*oci_',
      
      // SQLite
      'sqlite_',
      'sqlite3::',
      'sqlite error',
      
      // Generic SQL
      'sql error',
      'syntax error in query',
      'unexpected end of sql command',
      'table.*doesn\'t exist',
      'column.*not found',
      'ambiguous column name'
    ];

    // Check for SQL errors
    for (const error of sqlErrors) {
      const regex = new RegExp(error, 'i');
      if (regex.test(dataLower)) {
        analysis.indicators.push(`Found SQL error pattern: ${error}`);
        analysis.confidence = 95; // High confidence
        return true;
      }
    }

    // Boolean-based blind SQLi detection
    // Check if different boolean payloads give different response lengths
    if (response.data) {
      const responseLength = data.length;
      // Store for blind SQLi comparison (would need baseline)
      analysis.details.responseLength = responseLength;
    }

    // Check for timing-based indicators (already done in exploitationEngine)
    if (response.timing && response.timing > 5000) {
      analysis.indicators.push('Response timing anomaly (potential time-based SQLi)');
      analysis.confidence = 70;
    }

    return analysis.indicators.length > 0;
  }

  /**
   * Analyze XSS response
   */
  static _analyzeXSSResponse(response, payload, analysis) {
    const data = String(response.data || '');
    const payloadStr = String(payload.payload || '');

    // REAL bug bounty XSS detection patterns
    
    // 1. Check if payload is reflected WITHOUT encoding (CRITICAL!)
    if (data.includes(payloadStr)) {
      analysis.indicators.push('⚠️ Payload reflected UNENCODED in response');
      analysis.confidence = 90;
      return true;
    }

    // 2. Check for partial reflection (bypass attempts)
    const partialPayload = payloadStr.substring(0, Math.min(10, payloadStr.length));
    if (data.includes(partialPayload)) {
      analysis.indicators.push('Partial payload reflection detected');
      analysis.confidence = 60;
    }

    // 3. Check if dangerous tags are reflected
    const dangerousTags = ['<script', '<img', '<iframe', '<svg', '<object', '<embed', 'onerror=', 'onload=', 'onclick=', 'javascript:'];
    for (const tag of dangerousTags) {
      if (data.toLowerCase().includes(tag.toLowerCase())) {
        analysis.indicators.push(`Dangerous tag found in response: ${tag}`);
        analysis.confidence = Math.max(analysis.confidence || 0, 80);
        return true;
      }
    }

    // 4. Check for HTML context breaks
    const contextBreaks = ['</script>', '</style>', '</title>', '-->', '*/'];
    for (const breakStr of contextBreaks) {
      if (data.includes(breakStr) && payloadStr.includes(breakStr)) {
        analysis.indicators.push(`Context break possible: ${breakStr}`);
        analysis.confidence = 75;
        return true;
      }
    }

    // 5. Check if payload is HTML encoded (likely SAFE, not vulnerable)
    const encoded = this._htmlEncode(payloadStr);
    if (data.includes(encoded)) {
      analysis.indicators.push('✓ Payload was HTML encoded (properly sanitized)');
      analysis.confidence = 0; // NOT vulnerable
      return false;
    }

    // 6. Check response headers for XSS protection
    const headers = response.headers || {};
    if (headers['x-xss-protection'] === '0' || !headers['content-security-policy']) {
      analysis.indicators.push('Missing XSS protection headers');
      analysis.confidence = Math.max(analysis.confidence || 0, 40);
    }

    return analysis.indicators.length > 0 && analysis.confidence > 50;
  }

  /**
   * Analyze SSRF response
   */
  static _analyzeSSRFResponse(response, analysis) {
    const data = response.data || '';
    const localIndicators = [
      'localhost', '127.0.0.1', '192.168.', '10.0.', '172.16.',
      'admin panel', 'internal', 'metadata'
    ];

    for (const indicator of localIndicators) {
      if (data.toLowerCase().includes(indicator.toLowerCase())) {
        analysis.indicators.push(`Detected local content: ${indicator}`);
        return true;
      }
    }

    return false;
  }

  /**
   * Analyze Path Traversal response
   */
  static _analyzePathTraversalResponse(response, analysis) {
    const data = response.data || '';
    const fileIndicators = [
      'root:', 'daemon:', 'bin:', 'sys:', // /etc/passwd indicators
      '[boot loader]', '[operating system]', // win.ini indicators
      '<?php', '<?xml', 'BEGIN RSA PRIVATE KEY' // File content indicators
    ];

    for (const indicator of fileIndicators) {
      if (data.includes(indicator)) {
        analysis.indicators.push(`Detected file content: ${indicator}`);
        return true;
      }
    }

    return false;
  }

  /**
   * Analyze RCE response
   */
  static _analyzeRCEResponse(response, analysis) {
    const data = response.data || '';
    const rceIndicators = [
      'uid=', 'gid=', 'groups=', 'root', 'www-data',
      'C:\\\\', 'Windows\\\\System32'
    ];

    for (const indicator of rceIndicators) {
      if (data.includes(indicator)) {
        analysis.indicators.push(`Detected command output: ${indicator}`);
        return true;
      }
    }

    return false;
  }

  /**
   * Analyze XXE response
   */
  static _analyzeXXEResponse(response, analysis) {
    const data = response.data || '';
    const xxeIndicators = [
      'root:', 'DOCTYPE', 'ENTITY', 'SYSTEM',
      'XML parsing error', 'XXE'
    ];

    for (const indicator of xxeIndicators) {
      if (data.includes(indicator)) {
        analysis.indicators.push(`Detected XXE indicator: ${indicator}`);
        return true;
      }
    }

    return false;
  }

  /**
   * Analyze LFI response
   */
  static _analyzeLFIResponse(response, analysis) {
    return this._analyzePathTraversalResponse(response, analysis);
  }

  /**
   * Generic response analysis
   */
  static _analyzeGenericResponse(response, analysis) {
    if (response.status && (response.status < 400 || response.status === 403)) {
      analysis.indicators.push('Unexpected response behavior');
      return true;
    }
    return false;
  }

  /**
   * Check for false positives
   */
  static detectFalsePositives(response, vulnType) {
    const data = response.data || '';
    const falsePositiveIndicators = {
      'SQLi': ['SQL tutorial', 'Learn SQL', 'SQL syntax'],
      'XSS': ['XSS protection', 'CSP', 'X-XSS-Protection'],
      'PathTraversal': ['documentation', 'help', 'learning'],
      'RCE': ['example uid=', 'documentation']
    };

    const indicators = falsePositiveIndicators[vulnType] || [];
    for (const indicator of indicators) {
      if (data.toLowerCase().includes(indicator.toLowerCase())) {
        return true;
      }
    }

    return false;
  }

  /**
   * Extract useful data from response
   */
  static extractData(response, extractionPatterns = null) {
    const data = response.data || '';
    const extracted = [];

    if (!extractionPatterns) {
      extractionPatterns = [
        /api[_-]?key\s*[:=]\s*['"]?([^'"}\n]+)/gi,
        /password\s*[:=]\s*['"]?([^'"}\n]+)/gi,
        /token\s*[:=]\s*['"]?([^'"}\n]+)/gi,
        /secret\s*[:=]\s*['"]?([^'"}\n]+)/gi
      ];
    }

    extractionPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(data)) !== null) {
        extracted.push(match[1]);
      }
    });

    return extracted;
  }

  /**
   * Helper: HTML encode
   */
  static _htmlEncode(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Analyze response headers for security issues
   */
  static analyzeSecurityHeaders(headers) {
    const issues = [];
    const requiredHeaders = {
      'Content-Security-Policy': 'CSP Header missing',
      'X-Content-Type-Options': 'X-Content-Type-Options missing',
      'X-Frame-Options': 'X-Frame-Options missing (clickjacking risk)',
      'Strict-Transport-Security': 'HSTS Header missing'
    };

    Object.entries(requiredHeaders).forEach(([header, issue]) => {
      if (!headers[header.toLowerCase()]) {
        issues.push(issue);
      }
    });

    return issues;
  }
}

module.exports = ResponseAnalyzer;
