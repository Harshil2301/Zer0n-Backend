// Phase 1: API Discovery Service - Find REST, GraphQL, SOAP endpoints
const axios = require('axios');

class APIDiscoveryService {
  /**
   * Discover APIs on a domain
   */
  static async discoverAPIs(domain) {
    const apis = {
      rest: [],
      graphql: [],
      soap: [],
      swagger: [],
      postman: []
    };

    try {
      // Check for Swagger/OpenAPI
      const swaggerEndpoints = await this._findSwagger(domain);
      apis.swagger = swaggerEndpoints;

      // Check for GraphQL
      const graphqlEndpoints = await this._findGraphQL(domain);
      apis.graphql = graphqlEndpoints;

      // Check for SOAP
      const soapEndpoints = await this._findSOAP(domain);
      apis.soap = soapEndpoints;

      // Check for REST API patterns
      const restEndpoints = await this._findREST(domain);
      apis.rest = restEndpoints;

      // Check for Postman docs
      const postmanDocs = await this._findPostmanDocs(domain);
      apis.postman = postmanDocs;

      return {
        success: true,
        domain,
        apis
      };
    } catch (error) {
      console.error('API discovery error:', error);
      return {
        success: false,
        error: error.message,
        apis
      };
    }
  }

  /**
   * Find Swagger/OpenAPI endpoints
   */
  static async _findSwagger(domain) {
    const endpoints = [
      '/swagger.json',
      '/swagger.yaml',
      '/api/swagger.json',
      '/api-docs',
      '/api-docs/swagger.json',
      '/swagger-ui',
      '/swagger-ui.html',
      '/openapi.json',
      '/v1/openapi.json',
      '/docs',
      '/api/docs'
    ];

    const found = [];

    for (const endpoint of endpoints) {
      try {
        const url = `https://${domain}${endpoint}`;
        const response = await axios.get(url, { timeout: 5000 });
        
        if (response.status === 200) {
          found.push({
            endpoint,
            url,
            type: 'swagger/openapi',
            status: response.status
          });
        }
      } catch (error) {
        // Not found
      }
    }

    return found;
  }

  /**
   * Find GraphQL endpoints
   */
  static async _findGraphQL(domain) {
    const endpoints = [
      '/graphql',
      '/api/graphql',
      '/v1/graphql',
      '/graphql/api',
      '/graph'
    ];

    const found = [];

    for (const endpoint of endpoints) {
      try {
        const url = `https://${domain}${endpoint}`;
        
        // Try POST request with GraphQL query
        const response = await axios.post(url, 
          { query: '{ __typename }' },
          { 
            timeout: 5000,
            headers: { 'Content-Type': 'application/json' }
          }
        );

        if (response.status === 200) {
          found.push({
            endpoint,
            url,
            type: 'graphql',
            status: response.status,
            introspectionAvailable: this._checkGraphQLIntrospection(response.data)
          });
        }
      } catch (error) {
        // Not found
      }
    }

    return found;
  }

  /**
   * Check if GraphQL introspection is available
   */
  static _checkGraphQLIntrospection(data) {
    if (typeof data === 'string') {
      return data.includes('__schema');
    }
    return JSON.stringify(data).includes('__schema');
  }

  /**
   * Find SOAP endpoints
   */
  static async _findSOAP(domain) {
    const endpoints = [
      '/ws',
      '/webservice',
      '/soap',
      '/service',
      '/web-services',
      '/axis2/services',
      '/axis/services',
      '/services',
      '/api/soap'
    ];

    const found = [];

    for (const endpoint of endpoints) {
      try {
        const url = `https://${domain}${endpoint}`;
        const response = await axios.get(url, { timeout: 5000 });

        if (response.status === 200 && (
          response.data.includes('wsdl') || 
          response.data.includes('soap') ||
          response.data.includes('definitions')
        )) {
          found.push({
            endpoint,
            url,
            type: 'soap/wsdl',
            status: response.status
          });
        }
      } catch (error) {
        // Not found
      }
    }

    return found;
  }

  /**
   * Find REST API patterns
   */
  static async _findREST(domain) {
    const patterns = [
      '/api',
      '/api/v1',
      '/api/v2',
      '/v1/api',
      '/v2/api',
      '/rest',
      '/rest/api',
      '/public/api'
    ];

    const found = [];

    for (const pattern of patterns) {
      try {
        const url = `https://${domain}${pattern}`;
        const response = await axios.get(url, { timeout: 5000 });

        if (response.status === 200 || response.status === 400) {
          found.push({
            endpoint: pattern,
            url,
            type: 'rest',
            status: response.status
          });
        }
      } catch (error) {
        // Not found
      }
    }

    return found;
  }

  /**
   * Find Postman API documentation
   */
  static async _findPostmanDocs(domain) {
    try {
      // Common Postman documentation URLs
      const response = await axios.get(
        `https://documenter.getpostman.com/view?domain=${domain}`,
        { timeout: 5000 }
      );

      if (response.status === 200) {
        return [{
          type: 'postman',
          url: `https://documenter.getpostman.com/view?domain=${domain}`,
          found: true
        }];
      }
    } catch (error) {
      // Not found
    }

    return [];
  }

  /**
   * Introspect GraphQL schema
   */
  static async introspectGraphQL(endpoint) {
    const introspectionQuery = `
      query {
        __schema {
          types {
            name
            kind
            fields {
              name
              type { name kind }
            }
          }
        }
      }
    `;

    try {
      const response = await axios.post(endpoint,
        { query: introspectionQuery },
        {
          timeout: 10000,
          headers: { 'Content-Type': 'application/json' }
        }
      );

      return {
        success: true,
        schema: response.data
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = APIDiscoveryService;
