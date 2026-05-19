// Phase 1: Directory & File Fuzzer (like ffuf, gobuster, dirsearch)
const axios = require('axios');

class DirectoryFuzzer {
  /**
   * Fuzz for common directories and files
   */
  static async fuzzDirectories(baseUrl) {
    console.log(`    🔨 Fuzzing directories and files...`);
    const found = [];

    // Common wordlist (SecLists-inspired)
    const wordlist = [
      'admin', 'api', 'login', 'dashboard', 'config', 'backup',
      'test', 'dev', 'staging', 'debug', 'console', 'panel',
      'upload', 'uploads', 'files', 'images', 'assets', 'static',
      'js', 'css', 'include', 'includes', 'lib', 'libs',
      'vendor', 'node_modules', 'modules', 'plugins', 'extensions',
      'user', 'users', 'account', 'accounts', 'profile', 'profiles',
      'search', 'api/v1', 'api/v2', 'rest', 'graphql',
      'admin.php', 'login.php', 'config.php', 'phpinfo.php',
      'info.php', 'test.php', 'admin/login', 'wp-admin',
      '.git', '.env', '.htaccess', 'web.config', 'robots.txt',
      'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
      'readme.md', 'README.md', 'LICENSE', 'package.json',
      'composer.json', '.DS_Store', 'backup.sql', 'database.sql'
    ];

    const urlObj = new URL(baseUrl);
    const baseUrlStr = `${urlObj.protocol}//${urlObj.hostname}`;

    // Test each path (with rate limiting)
    for (let i = 0; i < Math.min(wordlist.length, 30); i++) {
      const path = wordlist[i];
      try {
        const testUrl = `${baseUrlStr}/${path}`;
        const response = await axios.get(testUrl, {
          timeout: 5000,
          headers: { 'User-Agent': 'Mozilla/5.0' },
          validateStatus: () => true,
          maxRedirects: 0
        });

        // Found if status is 200, 301, 302, 403 (forbidden = exists!)
        if ([200, 301, 302, 403].includes(response.status)) {
          found.push({
            url: testUrl,
            status: response.status,
            method: 'GET',
            type: 'fuzzed'
          });
          console.log(`       ✓ Found: ${path} [${response.status}]`);
        }

        // Rate limiting - be respectful!
        await new Promise(resolve => setTimeout(resolve, 200));
      } catch (error) {
        // Not found or error, skip
      }
    }

    console.log(`       ✓ Fuzzing complete: ${found.length} paths discovered`);
    return found;
  }

  /**
   * Fuzz parameters on a given endpoint
   */
  static async fuzzParameters(endpoint, paramWordlist = null) {
    const params = paramWordlist || [
      'id', 'user', 'username', 'email', 'name', 'search', 'q',
      'query', 'page', 'cat', 'category', 'file', 'path', 'url',
      'redirect', 'return', 'callback', 'ajax', 'action', 'cmd',
      'exec', 'command', 'debug', 'test', 'admin', 'token'
    ];

    const foundParams = [];
    const baseUrl = new URL(endpoint.url);

    for (const param of params.slice(0, 15)) {
      try {
        baseUrl.searchParams.set(param, 'test');
        const testUrl = baseUrl.toString();

        const response = await axios.get(testUrl, {
          timeout: 5000,
          headers: { 'User-Agent': 'Mozilla/5.0' },
          validateStatus: () => true
        });

        // Parameter exists if response differs or has 200
        if (response.status === 200) {
          foundParams.push({
            name: param,
            value: 'test',
            type: 'query',
            location: 'query'
          });
        }

        baseUrl.searchParams.delete(param);
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        // Skip
      }
    }

    return foundParams;
  }
}

module.exports = DirectoryFuzzer;
