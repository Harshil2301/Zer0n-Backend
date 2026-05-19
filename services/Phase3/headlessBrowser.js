// Phase 3: Headless Browser Integration - XSS detection
const puppeteer = require('puppeteer');

class HeadlessBrowserService {
  /**
   * Initialize browser instance
   */
  static async initBrowser() {
    try {
      const browser = await puppeteer.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage'
        ]
      });
      return browser;
    } catch (error) {
      console.error('Error launching browser:', error);
      throw error;
    }
  }

  /**
   * Test for XSS vulnerabilities
   */
  static async testXSS(url, parameter, payload) {
    let browser;
    try {
      browser = await this.initBrowser();
      const page = await browser.newPage();

      // Listen for console messages and alerts
      const alerts = [];
      const consoleLogs = [];
      let xssDetected = false;

      page.on('console', msg => {
        consoleLogs.push(msg.text());
      });

      page.on('dialog', async dialog => {
        alerts.push(dialog.message());
        xssDetected = true;
        await dialog.accept();
      });

      // Navigate and wait for response
      try {
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 10000 });
      } catch (e) {
        // Page might not exist, continue anyway
      }

      // Inject payload
      try {
        await page.evaluate((paramName, paramValue) => {
          // Try to find and fill form input
          const input = document.querySelector(`input[name="${paramName}"]`);
          if (input) {
            input.value = paramValue;
            input.dispatchEvent(new Event('change'));
            input.dispatchEvent(new Event('blur'));
          }
        }, parameter.name, payload.payload);
      } catch (e) {
        console.error('Error injecting payload:', e);
      }

      // Wait for potential JavaScript execution
      await new Promise(resolve => setTimeout(resolve, 2000));

      const pageContent = await page.content();

      return {
        success: true,
        xssDetected,
        alerts,
        consoleLogs,
        contentSnippet: pageContent.substring(0, 300)
      };
    } catch (error) {
      console.error('XSS test error:', error);
      return {
        success: false,
        error: error.message,
        xssDetected: false
      };
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }

  /**
   * Test for DOM-based XSS
   */
  static async testDOMXSS(url) {
    let browser;
    try {
      browser = await this.initBrowser();
      const page = await browser.newPage();

      await page.goto(url, { waitUntil: 'networkidle2', timeout: 10000 });

      // Check for dangerous DOM operations
      const domIssues = await page.evaluate(() => {
        const issues = [];

        // Check for innerHTML assignments
        const script = document.querySelector('script');
        if (script && script.textContent) {
          if (script.textContent.includes('innerHTML')) {
            issues.push('innerHTML usage detected');
          }
          if (script.textContent.includes('eval')) {
            issues.push('eval() usage detected');
          }
        }

        return issues;
      });

      return {
        success: true,
        domIssues,
        vulnerabilities: domIssues.length > 0
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }

  /**
   * Check JavaScript errors on page
   */
  static async checkJSErrors(url) {
    let browser;
    try {
      browser = await this.initBrowser();
      const page = await browser.newPage();

      const errors = [];

      page.on('error', err => {
        errors.push(err.toString());
      });

      page.on('pageerror', err => {
        errors.push(err.toString());
      });

      await page.goto(url, { waitUntil: 'networkidle2', timeout: 10000 });

      return {
        success: true,
        errors,
        hasErrors: errors.length > 0
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }

  /**
   * Extract JavaScript files
   */
  static async extractJavaScript(url) {
    let browser;
    try {
      browser = await this.initBrowser();
      const page = await browser.newPage();

      const jsFiles = [];

      page.on('response', async response => {
        if (response.request().resourceType() === 'script') {
          jsFiles.push(response.url());
        }
      });

      await page.goto(url, { waitUntil: 'networkidle2', timeout: 10000 });

      return {
        success: true,
        jsFiles: Array.from(new Set(jsFiles))
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        jsFiles: []
      };
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }
}

module.exports = HeadlessBrowserService;
