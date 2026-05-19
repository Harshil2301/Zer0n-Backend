// Gemini API Integration - AI-powered remediation suggestions
const { GoogleGenerativeAI } = require('@google/generative-ai');

class GeminiIntegration {
  static client = null;
  static apiKey = process.env.GEMINI_API_KEY || 'AIzaSyAwDdHV9jF2PTF96BKjJeqez6OyXJJvko8';

  /**
   * Initialize Gemini client
   */
  static initialize() {
    if (!this.client) {
      try {
        this.client = new GoogleGenerativeAI(this.apiKey);
      } catch (error) {
        console.error('Error initializing Gemini:', error);
      }
    }
    return this.client;
  }

  /**
   * Generate remediation suggestions
   */
  static async generateRemediationSuggestions(vulnerability) {
    try {
      const client = this.initialize();
      const model = client.getGenerativeModel({ model: 'gemini-pro' });

      const prompt = `As a cybersecurity expert, provide detailed remediation steps for the following vulnerability:

Type: ${vulnerability.type}
Endpoint: ${vulnerability.endpoint}
Parameter: ${vulnerability.parameter}
Severity: ${vulnerability.severity}
Description: ${vulnerability.description || 'N/A'}

Please provide:
1. Step-by-step remediation steps
2. Code examples in common languages (PHP, Python, Node.js, Java)
3. Testing methods to verify the fix
4. Recommended security best practices to prevent similar issues

Format the response in clear, actionable sections.`;

      const result = await model.generateContent(prompt);
      const text = result.response.text();

      return {
        success: true,
        remediation: text,
        vulnerability: vulnerability.type
      };
    } catch (error) {
      console.error('Gemini remediation error:', error);
      return {
        success: false,
        error: error.message,
        fallbackRemediation: this._getFallbackRemediation(vulnerability.type)
      };
    }
  }

  /**
   * Generate detailed report with AI analysis
   */
  static async generateDetailedReport(vulnerabilities) {
    try {
      const client = this.initialize();
      const model = client.getGenerativeModel({ model: 'gemini-pro' });

      const vulnSummary = vulnerabilities.map(v => 
        `- ${v.type} on ${v.endpoint} (${v.parameter}): ${v.severity}`
      ).join('\n');

      const prompt = `As a security consultant, analyze these vulnerabilities and provide a comprehensive report:

${vulnSummary}

Please provide:
1. Overall risk assessment
2. Priority order for remediation
3. Estimated time to fix each
4. Impact if left unpatched
5. Long-term security recommendations

Make it suitable for executive summary.`;

      const result = await model.generateContent(prompt);
      const text = result.response.text();

      return {
        success: true,
        analysis: text
      };
    } catch (error) {
      console.error('Gemini analysis error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get fallback remediation
   */
  static _getFallbackRemediation(vulnType) {
    const remediations = {
      'SQLi': `### SQL Injection Remediation

1. **Use Parameterized Queries/Prepared Statements**
   - PHP: Use mysqli/PDO with prepared statements
   - Python: Use parameterized queries with database libraries
   - Node.js: Use query parameters with mysql2 or sequelize

2. **Input Validation**
   - Whitelist allowed characters
   - Validate data types and lengths

3. **Code Example (Node.js):**
   \`\`\`javascript
   const query = 'SELECT * FROM users WHERE username = ?';
   connection.execute(query, [username], (err, results) => {
     // Handle results safely
   });
   \`\`\`

4. **Testing:**
   - Test with payloads like ' OR '1'='1
   - Use SQL injection testing tools
   - Perform code review`,

      'XSS': `### Cross-Site Scripting (XSS) Remediation

1. **Output Encoding**
   - HTML encode all user input before display
   - Use context-specific encoding (HTML, JS, URL, CSS)

2. **Content Security Policy**
   - Implement CSP headers
   - Restrict script execution sources

3. **Code Example (Node.js):**
   \`\`\`javascript
   const escapeHtml = require('escape-html');
   app.get('/user/:id', (req, res) => {
     const userId = escapeHtml(req.params.id);
     res.send(\`User: \${userId}\`);
   });
   \`\`\`

4. **Testing:**
   - Test with <script>alert(1)</script>
   - Use XSS scanning tools
   - Verify CSP headers in browser`,

      'PathTraversal': `### Path Traversal Remediation

1. **Path Validation**
   - Normalize paths using canonical paths
   - Whitelist allowed directories
   - Prevent ../ sequences

2. **Code Example (Node.js):**
   \`\`\`javascript
   const path = require('path');
   const filepath = path.join(__dirname, 'uploads', req.query.file);
   if (!filepath.startsWith(__dirname)) {
     return res.status(403).send('Access denied');
   }
   \`\`\`

3. **Implementation:**
   - Use framework built-in path utilities
   - Implement strict access controls
   - Log suspicious requests

4. **Testing:**
   - Test with ../../../etc/passwd
   - Verify path restriction`,

      'RCE': `### Remote Code Execution (RCE) Remediation

1. **Avoid Shell Commands**
   - Never pass user input to system commands
   - Use safe APIs instead of exec/system

2. **Sandboxing**
   - Run code in isolated environments
   - Limit system permissions

3. **Code Example (Node.js):**
   \`\`\`javascript
   // AVOID: const output = exec(\`echo \${userInput}\`);
   // USE: Safe alternative
   const {spawn} = require('child_process');
   const child = spawn('echo', ['safe', 'args']);
   \`\`\`

4. **Testing:**
   - Perform security code review
   - Use WAF/IPS for command injection patterns`,

      'SSRF': `### Server-Side Request Forgery (SSRF) Remediation

1. **URL Validation**
   - Whitelist allowed domains
   - Block local IP ranges (127.0.0.1, 192.168.x.x, etc)

2. **Code Example:**
   \`\`\`javascript
   const isValidURL = (url) => {
     const parsed = new URL(url);
     const blocked = ['localhost', '127.0.0.1', '0.0.0.0'];
     if (blocked.includes(parsed.hostname)) return false;
     return true;
   };
   \`\`\`

3. **Network Segmentation**
   - Isolate internal services
   - Use firewall rules

4. **Testing:**
   - Test with http://localhost/admin
   - Verify whitelist enforcement`
    };

    return remediations[vulnType] || 'Please consult security documentation for this vulnerability type.';
  }

  /**
   * Generate code fix suggestions
   */
  static async generateCodeFix(vulnerability, codeSnippet) {
    try {
      const client = this.initialize();
      const model = client.getGenerativeModel({ model: 'gemini-pro' });

      const prompt = `As a code security expert, provide a secure version of this code that fixes the ${vulnerability.type} vulnerability:

Current Code:
\`\`\`
${codeSnippet}
\`\`\`

Please provide:
1. Secure version of the code
2. Explanation of changes
3. Why this fix works
4. Any additional security considerations

Format as clear code blocks.`;

      const result = await model.generateContent(prompt);
      const text = result.response.text();

      return {
        success: true,
        fix: text
      };
    } catch (error) {
      console.error('Gemini code fix error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Stream remediation response
   */
  static async *streamRemediationSuggestions(vulnerability) {
    try {
      const client = this.initialize();
      const model = client.getGenerativeModel({ model: 'gemini-pro' });

      const prompt = `Provide detailed remediation for ${vulnerability.type} vulnerability found on ${vulnerability.endpoint}`;

      const result = await model.generateContentStream(prompt);

      for await (const chunk of result.stream) {
        yield chunk.text();
      }
    } catch (error) {
      console.error('Streaming error:', error);
      yield `Error: ${error.message}`;
    }
  }
}

module.exports = GeminiIntegration;
