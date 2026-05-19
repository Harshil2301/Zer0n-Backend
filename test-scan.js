#!/usr/bin/env node

/**
 * Test Script: Automatic Scan for testphp.vulnweb.com
 * This script will start a vulnerability scan against the test domain
 */

const axios = require('axios');
const io = require('socket.io-client');

const BACKEND_URL = 'http://localhost:5000';
const TEST_DOMAIN = 'testphp.vulnweb.com';

console.log('\n' + '='.repeat(70));
console.log('🚀 ZerOn Vulnerability Scanner - Automated Test');
console.log('='.repeat(70));
console.log(`📍 Target Domain: ${TEST_DOMAIN}`);
console.log(`🔗 Backend URL: ${BACKEND_URL}`);
console.log('='.repeat(70) + '\n');

// Connect to Socket.io for real-time updates
const socket = io(BACKEND_URL, {
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  reconnectionAttempts: 5
});

let scanId = null;

socket.on('connect', () => {
  console.log('✓ Connected to backend via Socket.io\n');
});

socket.on('connect_error', (error) => {
  console.error('✗ Socket connection error:', error.message);
});

socket.on('disconnect', () => {
  console.log('\n✗ Disconnected from backend');
});

// Start the scan
async function startScan() {
  try {
    console.log('📝 Starting scan...\n');
    
    const response = await axios.post(`${BACKEND_URL}/api/scan/start`, {
      domain: TEST_DOMAIN,
      plan: 'pro',
      scope: [TEST_DOMAIN, `www.${TEST_DOMAIN}`]
    });

    scanId = response.data.scanId;
    console.log(`✓ Scan started successfully!`);
    console.log(`📊 Scan ID: ${scanId}`);
    console.log(`⏱️  Estimated Duration: ${response.data.estimatedDuration / 1000 / 60} minutes\n`);

    // Join the scan room for updates
    socket.emit('join_scan', { scanId });

    // Listen for progress updates
    socket.on(`progress_${scanId}`, (data) => {
      const barLength = 40;
      const filledLength = Math.round((data.progress / 100) * barLength);
      const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
      
      console.log(`\n🔄 ${data.phase}`);
      console.log(`   [${bar}] ${data.progress}%`);
      console.log(`   Status: ${data.status}`);
      console.log(`   Findings: ${data.findings}`);

      if (data.progress === 100 && data.findings > 0) {
        setTimeout(() => {
          getScanResults();
        }, 2000);
      }
    });

    // Check status periodically
    const statusInterval = setInterval(async () => {
      try {
        const statusResponse = await axios.get(
          `${BACKEND_URL}/api/scan/${scanId}/status`
        );
        
        if (statusResponse.data.status === 'completed') {
          clearInterval(statusInterval);
          console.log('\n✓ Scan completed!\n');
          await getScanResults();
          
          // Cleanup
          setTimeout(() => {
            socket.emit('leave_scan', { scanId });
            socket.disconnect();
            process.exit(0);
          }, 3000);
        }
      } catch (error) {
        console.error('Error checking status:', error.message);
      }
    }, 5000);

    // Timeout after 10 minutes
    setTimeout(() => {
      clearInterval(statusInterval);
      console.log('\n⏱️  Scan timeout - stopping test');
      socket.disconnect();
      process.exit(0);
    }, 600000);

  } catch (error) {
    console.error('✗ Error starting scan:', error.message);
    process.exit(1);
  }
}

// Get and display scan results
async function getScanResults() {
  try {
    const response = await axios.get(`${BACKEND_URL}/api/scan/${scanId}/results`);
    const data = response.data;

    console.log('\n' + '='.repeat(70));
    console.log('📊 SCAN RESULTS');
    console.log('='.repeat(70));
    console.log(`\n🎯 Target: ${data.domain}`);
    console.log(`📝 Scan ID: ${data.scanId}`);
    console.log(`⏱️  Duration: ${data.duration} seconds`);
    console.log(`📈 Total Vulnerabilities: ${data.statistics.totalVulnerabilities}\n`);

    console.log('Severity Breakdown:');
    console.log(`  🔴 Critical: ${data.statistics.bySeverity.critical}`);
    console.log(`  🟠 High: ${data.statistics.bySeverity.high}`);
    console.log(`  🟡 Medium: ${data.statistics.bySeverity.medium}`);
    console.log(`  🔵 Low: ${data.statistics.bySeverity.low}\n`);

    if (data.vulnerabilities.length > 0) {
      console.log('Detailed Findings:\n');
      
      data.vulnerabilities.forEach((vuln, index) => {
        const severityEmoji = {
          critical: '🔴',
          high: '🟠',
          medium: '🟡',
          low: '🔵',
          info: 'ℹ️'
        }[vuln.severity] || '❓';

        console.log(`${index + 1}. ${severityEmoji} ${vuln.type}`);
        console.log(`   Severity: ${vuln.severity.toUpperCase()} (CVSS: ${vuln.cvss || 'N/A'})`);
        console.log(`   Endpoint: ${vuln.endpoint}`);
        if (vuln.parameter) console.log(`   Parameter: ${vuln.parameter}`);
        if (vuln.description) console.log(`   Description: ${vuln.description}`);
        if (vuln.payload) console.log(`   Payload: ${vuln.payload}`);
        console.log('');
      });
    }

    console.log('='.repeat(70));
    console.log('✓ Test completed successfully!');
    console.log('='.repeat(70) + '\n');

  } catch (error) {
    console.error('✗ Error retrieving results:', error.message);
  }
}

// Start the test
startScan();
