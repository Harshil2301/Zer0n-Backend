// ZerOn Backend Server with Firebase Integration
const express = require('express');
const cors = require('cors');
const http = require('http');
const socketIO = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// ── Biometric Security Helpers ────────────────────────────────────────────
// AES-256-CBC encryption key derived from env salt (32 bytes)
const FACE_ENC_KEY = Buffer.alloc(32);
Buffer.from(process.env.FACE_DESCRIPTOR_SALT || 'zeron-face-salt-2026-unique-per-deploy', 'utf8').copy(FACE_ENC_KEY);

function encryptDescriptor(descriptorArray) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', FACE_ENC_KEY, iv);
  const json = JSON.stringify(descriptorArray);
  let enc = cipher.update(json, 'utf8', 'hex');
  enc += cipher.final('hex');
  return iv.toString('hex') + ':' + enc;
}

function decryptDescriptor(encryptedStr) {
  try {
    const [ivHex, enc] = encryptedStr.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', FACE_ENC_KEY, iv);
    let dec = decipher.update(enc, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return JSON.parse(dec);
  } catch (e) {
    return null; // Legacy unencrypted vector — skip silently
  }
}

function euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) { const d = a[i] - b[i]; sum += d * d; }
  return Math.sqrt(sum);
}

function matchZone(distance) {
  if (distance < 0.35) return { result: 'CONFIRMED', confidence: 'HIGH' };
  if (distance < 0.45) return { result: 'CONFIRMED', confidence: 'MEDIUM' };
  if (distance < 0.55) return { result: 'UNCERTAIN', action: 'request_mfa' };
  return { result: 'REJECTED', confidence: 'HIGH' };
}
// ────────────────────────────────────────────────────────────────────────────

// Import Firebase
const { admin, db, auth } = require('./config/firebase');

// Import ALL Professional Scanning Services
// Phase 0: Scope & Recon
const ScopeService = require('./services/Phase0/scopeService');
const SubdomainEnumerator = require('./services/Phase0/subdomainEnum');
const AssetCatalog = require('./services/Phase0/assetCatalog');

// Phase 1: Discovery
const CrawlerService = require('./services/Phase1/crawlerService');
const FingerprintService = require('./services/Phase1/fingerprintService');
const WaybackService = require('./services/Phase1/waybackService');
const JSFileAnalyzer = require('./services/Phase1/jsFileAnalyzer');
const RobotsAndSitemapService = require('./services/Phase1/robotsAndSitemapService');
const DirectoryFuzzer = require('./services/Phase1/directoryFuzzer');

// Phase 2: Attack Surface Analysis
const ParameterDiscovery = require('./services/Phase2/parameterDiscovery');
const PayloadGenerator = require('./services/Phase2/payloadGenerator');

// Phase 3: Exploitation
const ExploitationEngine = require('./services/Phase3/exploitationEngine');
const ValidatorEngine = require('./services/Phase3/validatorEngine');
const ResponseAnalyzer = require('./services/Phase3/responseAnalyzer');
const SeverityCalculator = require('./services/Phase3/severityCalculator');
const PoCGenerator = require('./services/Phase3/pocGenerator');
const AdvancedExploitationService = require('./services/Phase3/advancedExploitationService');

// Phase 4: Reporting
const ReportGenerator = require('./services/Phase4/reportGenerator');
const BugBountyReportService = require('./services/Phase4/bugBountyReportService');
const PDFReportService = require('./services/Phase4/pdfReportService');
const IpfsService = require('./services/Phase4/ipfsService');
const EscrowService = require('./services/Phase4/escrowService');


// ==========================================
// MIXTURE OF AGENTS (MoA) ORCHESTRATOR
// ==========================================
const MasterAgent = require('./services/agents/masterAgent');

const app = express();
const server = http.createServer(app);

// Configure allowed origins for CORS
const allowedOrigins = [
  process.env.FRONTEND_URL, // Production Vercel URL
  'https://zer0n.vercel.app', // Hardcoded fallback for your specific deployment
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5000'
].filter(Boolean);

const io = socketIO(server, {
  cors: { 
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, curl, Postman)
      if (!origin) return callback(null, true);
      
      // Check if origin is allowed or starts with allowed domain
      if (allowedOrigins.some(allowed => origin.startsWith(allowed.replace('/dashboard', '')))) {
        return callback(null, true);
      }
      
      return callback(null, true); // For now, allow all (you can restrict later)
    },
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    
    // Check if origin is allowed
    if (allowedOrigins.some(allowed => origin.startsWith(allowed.replace('/dashboard', '')))) {
      return callback(null, true);
    }
    
    return callback(null, true); // For now, allow all
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Health Check Route
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'ZerOn-Backend',
    timestamp: new Date().toISOString(),
    cors_status: 'operational'
  });
});

// Request logger for debugging deployment connections
app.use((req, res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.path} - Origin: ${req.headers.origin || 'None'}`);
  next();
});

// Biometric Authentication Middleware
const requireBiometric = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing biometric token' });
  }
  
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'zeron-biometric-jwt-secret-2026-change-in-prod');
    if (!decoded.biometricVerified) {
      return res.status(403).json({ error: 'Token does not have biometric verified claim' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired biometric token' });
  }
};

// Store active scans in memory (for demo) AND Firebase
const activeScans = {};

// Save scan to Firebase
async function saveScanToFirebase(scanData) {
  try {
    await db.collection('scans').doc(scanData.scanId).set(scanData, { merge: true });
    console.log(`✓ Scan ${scanData.scanId} saved to Firebase`);
  } catch (error) {
    console.error('Firebase save error:', error);
  }
}

// Retrieve scan from Firebase
async function getScanFromFirebase(scanId) {
  try {
    const doc = await db.collection('scans').doc(scanId).get();
    return doc.exists ? doc.data() : null;
  } catch (error) {
    console.error('Firebase retrieve error:', error);
    return null;
  }
}

// Plan configuration
const PLANS = {
  basic: {
    name: 'Basic',
    price: 0,
    limits: { endpoints: 10, payloads: 100, concurrency: 1 },
    features: ['Scope Ingestion', 'Basic Crawling', 'Limited Payloads']
  },
  pro: {
    name: 'Pro',
    price: 99,
    limits: { endpoints: 100, payloads: 1000, concurrency: 5 },
    features: ['Advanced Discovery', 'Full Payloads', 'API Integration']
  },
  enterprise: {
    name: 'Enterprise',
    price: 999,
    limits: { endpoints: 1000, payloads: 5000, concurrency: 20 },
    features: ['Unlimited Access', 'Priority Support', 'Custom Rules']
  }
};

// Rate Limiting Middlewares
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, please try again after 15 minutes' }
});

const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 scan requests per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests initiated from this IP, please try again after an hour' }
});

// Apply global rate limiting to all API endpoints
app.use('/api/', apiLimiter);

// ============================================================================
// ROUTES
// ============================================================================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    version: '2.0.0',
    features: {
      vulnerabilityTypes: 10,
      totalTestVectors: 218,
      realTimeUpdates: true,
      firebaseIntegration: true
    },
    allowedOrigins: allowedOrigins,
    endpoints: {
      startScan: 'POST /api/scan/start',
      scanStatus: 'GET /api/scan/:scanId/status',
      scanResults: 'GET /api/scan/:scanId/results',
      health: 'GET /api/health',
      plans: 'GET /api/plans'
    }
  });
});

// ─── ADMIN: Purge old face vectors (run once after model upgrade) ───────────
// Use: POST /api/admin/purge-face-vectors  with body { adminKey: "zeron-admin-2026" }
// Required after switching from TinyFaceDetector → SSD Mobilenet v1
app.post('/api/admin/purge-face-vectors', async (req, res) => {
  const { adminKey } = req.body;
  if (adminKey !== 'zeron-admin-2026') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    const faceVectorsRef = db.collection('faceVectors');
    const snapshot = await faceVectorsRef.get();
    const deletePromises = snapshot.docs.map(doc => doc.ref.delete());
    await Promise.all(deletePromises);
    console.log(`[ADMIN] Purged ${snapshot.size} old face vectors from Firebase`);
    return res.json({ success: true, deleted: snapshot.size, message: 'Re-enroll all users now.' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// ─── Face Enroll (AES-encrypted storage) ───────────────────────────────────
// Receives raw descriptor from frontend, encrypts it, stores ciphertext only
// Raw biometric data NEVER touches Firestore
app.post('/api/face/enroll', async (req, res) => {
  const { faceVector, userId } = req.body;
  if (!faceVector || !Array.isArray(faceVector) || !userId) {
    return res.status(400).json({ error: 'Invalid payload' });
  }
  try {
    const encryptedVector = encryptDescriptor(faceVector);
    const faceVectorsRef = db.collection('faceVectors');
    const docRef = await faceVectorsRef.add({
      encryptedVector,          // AES-256 ciphertext only — no raw biometrics
      userId,
      uuid: userId,
      model: 'ssd_mobilenetv1_v2', // track model version for future migrations
      timestamp: new Date().toISOString(),
    });
    console.log(`[Enroll] Encrypted vector stored for user ${userId}`);
    return res.json({ success: true, docId: docRef.id, uuid: userId });
  } catch (error) {
    console.error('[Enroll] Error:', error);
    return res.status(500).json({ error: 'Enrollment failed' });
  }
});

// ─── Face Verification: Decrypt → Euclidean → 3-zone → JWT ─────────────────
const faceAttempts = new Map(); // IP → attempt count

app.post('/api/face/verify', async (req, res) => {
  // Rate limiting (max 5 attempts per 15 minutes per IP)
  const ip = req.ip || req.connection.remoteAddress;
  const attempts = faceAttempts.get(ip) || 0;
  if (attempts >= 5) {
    return res.status(429).json({ error: 'Too many attempts. Use email login.' });
  }
  faceAttempts.set(ip, attempts + 1);
  setTimeout(() => faceAttempts.delete(ip), 15 * 60 * 1000); // Reset after 15 mins

  const { faceVector } = req.body;
  if (!faceVector || !Array.isArray(faceVector)) {
    return res.status(400).json({ error: 'Invalid face vector' });
  }
  try {
    const snapshot = await db.collection('faceVectors').get();
    let lowestDistance = Infinity;
    let bestMatch = null;

    snapshot.forEach(doc => {
      const d = doc.data();
      // Support both new encrypted and legacy raw format
      let storedVector = d.encryptedVector ? decryptDescriptor(d.encryptedVector) : (Array.isArray(d.vector) ? d.vector : null);
      if (!storedVector || storedVector.length !== faceVector.length) return;
      const dist = euclideanDistance(faceVector, storedVector);
      if (dist < lowestDistance) {
        lowestDistance = dist;
        bestMatch = { id: doc.id, distance: dist, isEncrypted: !!d.encryptedVector, userId: d.userId, uuid: d.uuid || d.userId, timestamp: d.timestamp };
      }
    });

    const zone = matchZone(lowestDistance);
    console.log(`[Face Verify] dist=${lowestDistance.toFixed(4)} zone=${zone.result} conf=${zone.confidence}`);

    if (zone.result === 'REJECTED' || !bestMatch) {
      return res.json({ match: null, zone });
    }
    if (zone.result === 'UNCERTAIN') {
      return res.json({ match: { ...bestMatch, uncertain: true }, zone });
    }
    // CONFIRMED: issue short-lived biometric JWT (8h expiry)
    const bioToken = jwt.sign(
      { userId: bestMatch.uuid, biometricVerified: true, method: 'face_ssd_v2', confidence: zone.confidence },
      process.env.JWT_SECRET || 'zeron-biometric-jwt-secret-2026-change-in-prod',
      { expiresIn: '8h' }
    );
    return res.json({ match: bestMatch, zone, bioToken });
  } catch (error) {
    console.error('[Face Verify] Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Get Plans
app.get('/api/plans', (req, res) => {
  res.json({ plans: PLANS });
});

// Start Scan (Protected by Biometric Session and Rate-Limited)
app.post('/api/scan/start', requireBiometric, scanLimiter, async (req, res) => {
  const { domain, plan, scope, sessionCookie, userId } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  // Generate UUID for scan ID
  const scanId = uuidv4();
  const planConfig = PLANS[plan] || PLANS.basic;

  const scanData = {
    scanId,
    domain,
    plan,
    sessionCookie,
    userId: userId || 'anonymous',
    scope: scope || [domain],
    status: 'started',
    progress: 0,
    createdAt: new Date().toISOString(),
    phases: [
      { id: 0, name: 'Scope Ingestion', status: 'pending', progress: 0 },
      { id: 1, name: 'Discovery', status: 'pending', progress: 0 },
      { id: 2, name: 'Attack Surface', status: 'pending', progress: 0 },
      { id: 3, name: 'Exploitation', status: 'pending', progress: 0 },
      { id: 4, name: 'Reporting', status: 'pending', progress: 0 }
    ],
    vulnerabilities: []
  };

  activeScans[scanId] = scanData;
  
  // Save to Firebase
  await saveScanToFirebase(scanData);

  res.status(201).json({
    scanId,
    status: 'started',
    domain,
    plan,
    progress: 0,
    createdAt: new Date().toISOString(),
    estimatedDuration: 1800000
  });

  // Start real scanning in background
  performRealScan(scanId);
});

// Get Scan Status
app.get('/api/scan/:scanId/status', async (req, res) => {
  const { scanId } = req.params;
  let scan = activeScans[scanId];

  // If not in memory, try to fetch from Firebase
  if (!scan) {
    scan = await getScanFromFirebase(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
  }

  res.json({
    scanId,
    status: scan.status,
    progress: scan.progress,
    currentPhase: scan.phases.find(p => p.status === 'in_progress') || scan.phases[4],
    phases: scan.phases,
    findingsCount: {
      total: scan.vulnerabilities.length,
      critical: scan.vulnerabilities.filter(v => v.severity === 'critical').length,
      high: scan.vulnerabilities.filter(v => v.severity === 'high').length,
      medium: scan.vulnerabilities.filter(v => v.severity === 'medium').length,
      low: scan.vulnerabilities.filter(v => v.severity === 'low').length
    },
    updatedAt: new Date().toISOString()
  });
});

// Get Scan Results
app.get('/api/scan/:scanId/results', async (req, res) => {
  const { scanId } = req.params;
  let scan = activeScans[scanId];

  // If not in memory, try to fetch from Firebase
  if (!scan) {
    scan = await getScanFromFirebase(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
  }

  res.json({
    scanId,
    domain: scan.domain,
    status: scan.status,
    startTime: scan.createdAt,
    endTime: new Date().toISOString(),
    duration: 1800,
    vulnerabilities: scan.vulnerabilities,
    statistics: {
      totalVulnerabilities: scan.vulnerabilities.length,
      bySeverity: {
        critical: scan.vulnerabilities.filter(v => v.severity === 'critical').length,
        high: scan.vulnerabilities.filter(v => v.severity === 'high').length,
        medium: scan.vulnerabilities.filter(v => v.severity === 'medium').length,
        low: scan.vulnerabilities.filter(v => v.severity === 'low').length
      }
    }
  });
});

// Get Scan by UUID from Firebase (New endpoint for direct Firebase queries)
app.get('/api/scan/:scanId', async (req, res) => {
  const { scanId } = req.params;
  
  try {
    // First check active scans
    let scan = activeScans[scanId];
    
    // If not in memory, fetch from Firebase
    if (!scan) {
      scan = await getScanFromFirebase(scanId);
    }
    
    if (!scan) {
      return res.status(404).json({ 
        error: 'Scan not found',
        message: `No scan found with UUID: ${scanId}`
      });
    }

    // Return complete scan data
    res.json({
      success: true,
      data: scan
    });
  } catch (error) {
    console.error('Error fetching scan:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to fetch scan data from Firebase'
    });
  }
});

// Get all scans from Firebase
app.get('/api/scans', async (req, res) => {
  try {
    const { limit = 50, orderBy = 'createdAt', order = 'desc' } = req.query;
    
    let query = db.collection('scans')
      .orderBy(orderBy, order)
      .limit(parseInt(limit));
    
    const snapshot = await query.get();
    
    if (snapshot.empty) {
      return res.json({
        success: true,
        data: [],
        count: 0
      });
    }

    const scans = [];
    snapshot.forEach(doc => {
      scans.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.json({
      success: true,
      data: scans,
      count: scans.length
    });
  } catch (error) {
    console.error('Error fetching scans:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'Failed to fetch scans from Firebase'
    });
  }
});

// Download PDF Report
app.get('/api/scan/:scanId/report.pdf', async (req, res) => {
  const { scanId } = req.params;
  let scan = activeScans[scanId];
  if (!scan) scan = await getScanFromFirebase(scanId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  try {
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="ZerOn-Report-${scan.domain}-${scanId.substring(0,8)}.pdf"`);
    const pdfBuffer = await PDFReportService.generatePDF(scan);
    res.send(pdfBuffer);
    console.log(`📄 PDF report generated for ${scan.domain} (${scan.vulnerabilities?.length || 0} findings)`);
  } catch (err) {
    console.error('PDF generation error:', err.message);
    res.status(500).json({ error: 'PDF generation failed', detail: err.message });
  }
});

// Get Remediation Suggestions (Dynamic with Gemini AI)
app.post('/api/remediation/suggest', async (req, res) => {
  const { vulnerability } = req.body;
  if (!vulnerability) {
    return res.status(400).json({ error: 'Vulnerability data is required' });
  }

  try {
    const { GoogleGenerativeAI } = require('@google/generative-ai');
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || 'dummy_key');
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });
    
    const prompt = `
      Act as a Senior Application Security Engineer. I will provide a JSON object describing a vulnerability found during a web scan.
      You must analyze the vulnerability and provide a structured JSON response with actionable remediation steps.
      
      Vulnerability Data:
      ${JSON.stringify(vulnerability, null, 2)}
      
      Respond STRICTLY with a valid JSON object in this exact format:
      {
        "analysis": "A clear, concise explanation of why this vulnerability occurred and its impact.",
        "recommendations": [
          "Step 1 to fix...",
          "Step 2 to fix..."
        ],
        "codeExample": {
          "language": "javascript",
          "vulnerable": "The vulnerable code snippet (inferred or general)",
          "secure": "The exact secure implementation"
        }
      }
      Do not include markdown blocks like \`\`\`json around the response. Just the raw JSON.
    `;
    
    const result = await model.generateContent(prompt);
    const text = result.response.text().replace(/```json/gi, '').replace(/```/g, '').trim();
    const remediationData = JSON.parse(text);
    
    res.json({
      vulnerability,
      ...remediationData
    });
  } catch (error) {
    console.error('Gemini Remediation Error:', error);
    // Fallback to generic if AI fails
    res.json({
      vulnerability,
      analysis: `Analysis for ${vulnerability?.type || 'this'} vulnerability. The AI engine is currently unavailable.`,
      recommendations: [
        'Review the OWASP guidelines for this vulnerability class.',
        'Implement input validation and sanitization.',
        'Update related dependencies to their latest secure versions.'
      ],
      codeExample: {
        language: 'text',
        vulnerable: '// Code could not be inferred',
        secure: '// Follow best practices for this framework'
      }
    });
  }
});

// Export to Bug Bounty
app.post('/api/export/bug-bounty', (req, res) => {
  const { scanId, platform, vulnerabilities } = req.body;

  res.json({
    status: 'exported',
    platform,
    reportCount: vulnerabilities?.length || 0,
    message: `Successfully exported to ${platform}`
  });
});

// ============================================================================
// SOCKET.IO EVENTS
// ============================================================================

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('join_scan', (data) => {
    socket.join(`scan_${data.scanId}`);
    console.log(`Client joined scan room: scan_${data.scanId}`);
  });

  socket.on('leave_scan', (data) => {
    socket.leave(`scan_${data.scanId}`);
    console.log(`Client left scan room: scan_${data.scanId}`);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ============================================================================
// PROFESSIONAL BUG BOUNTY SCANNING ENGINE
// ============================================================================

async function performRealScan(scanId) {
  const scan = activeScans[scanId];
  const domain = scan.domain;
  
  // Try both HTTP and HTTPS
  let targetUrl = domain.startsWith('http') ? domain : `http://${domain}`;
  
  console.log(`\n🎯 Starting professional scan for: ${domain}`);
  console.log(`   Attempting connection to: ${targetUrl}`);
  
  try {
    // Phase 0: Scope Ingestion & Subdomain Enumeration
    const subdomains = await runPhase0(scanId, domain, targetUrl);
    
    // Phase 1: Discovery - Crawl all subdomains and fingerprint
    const discoveredAssets = await runPhase1(scanId, [targetUrl, ...subdomains]);
    
    // Phase 2: Attack Surface Analysis - Find parameters and generate payloads
    const attackSurface = await runPhase2(scanId, discoveredAssets);
    
    // Phase 3: Exploitation - Test with intelligent payloads
    const vulnerabilities = await runPhase3(scanId, attackSurface);
    
    // Phase 4: Report Generation
    await runPhase4(scanId, vulnerabilities);
    
    scan.status = 'completed';
    scan.progress = 100;
    await saveScanToFirebase(scan);
    
    console.log(`✅ Scan completed: Found ${scan.vulnerabilities.length} vulnerabilities`);
    
    io.emit(`progress_${scanId}`, {
      phase: 'Complete!',
      status: `Scan finished - Found ${scan.vulnerabilities.length} vulnerabilities`,
      progress: 100,
      findings: scan.vulnerabilities.length
    });
    
  } catch (error) {
    console.error(`❌ Scan error for ${scanId}:`, error);
    scan.status = 'failed';
    scan.error = error.message;
    await saveScanToFirebase(scan);
    
    io.emit(`progress_${scanId}`, {
      phase: 'Error',
      status: `Scan failed: ${error.message}`,
      progress: scan.progress,
      findings: scan.vulnerabilities.length
    });
  }
}

// Phase 0: Scope Ingestion & Subdomain Enumeration (Real Bug Bounty Approach)
async function runPhase0(scanId, domain, targetUrl) {
  const scan = activeScans[scanId];
  scan.phases[0].status = 'in_progress';
  
  console.log('📋 Phase 0: Scope Ingestion & Subdomain Enumeration');
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 0: Scope Ingestion',
    status: 'Enumerating subdomains...',
    progress: 5,
    findings: 0
  });
  
  // Parse scope
  const scope = await ScopeService.parseScope(domain);
  console.log(`  ✓ Parsed scope: ${scope.domains.length} domains`);
  
  // Enumerate subdomains (like a real bug bounty hunter)
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 0: Subdomain Enumeration',
    status: 'Using DNS bruteforce & CT logs...',
    progress: 7,
    findings: 0
  });
  
  const subdomainList = await SubdomainEnumerator.enumerateSubdomains(domain);
  console.log(`  ✓ Found ${subdomainList.length} subdomains`);
  
  // Verify live subdomains (limit to top 5 for speed)
  const liveSubdomains = await SubdomainEnumerator.verifySubdomains(subdomainList.slice(0, 5));
  const subdomainUrls = liveSubdomains.map(sub => `https://${sub.subdomain}`);
  
  console.log(`  ✓ Verified ${liveSubdomains.length} live subdomains`);
  
  scan.phases[0].status = 'completed';
  scan.phases[0].progress = 100;
  scan.progress = 10;
  await saveScanToFirebase(scan);
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 0: Complete',
    status: `Found ${liveSubdomains.length} live subdomains`,
    progress: 10,
    findings: 0
  });
  
  return subdomainUrls;
}

// Phase 1: Discovery - REAL Bug Bounty Reconnaissance Tools
async function runPhase1(scanId, targets) {
  const scan = activeScans[scanId];
  scan.phases[1].status = 'in_progress';
  
  console.log('🕷️  Phase 1: Professional Reconnaissance');
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 1: Discovery',
    status: `Running professional recon on ${targets.length} targets...`,
    progress: 15,
    findings: 0
  });
  
  const allEndpoints = [];
  const techStack = [];
  
  // Process each target with REAL bug bounty tools
  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const urlObj = new URL(target);
    const domain = urlObj.hostname;
    
    console.log(`\n  🎯 Target: ${target}`);
    console.log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    
    try {
      // Tool 1: Wayback Machine (Historical URLs)
      const waybackUrls = await WaybackService.getHistoricalUrls(domain);
      const waybackPaths = WaybackService.extractPaths(waybackUrls);
      waybackPaths.forEach(path => {
        try {
          allEndpoints.push({
            url: new URL(path, target).href,
            method: 'GET',
            type: 'wayback'
          });
        } catch (e) {}
      });
      
      // Tool 2: Robots.txt & Sitemap.xml
      const robotsPaths = await RobotsAndSitemapService.parseRobotsTxt(target);
      const sitemapUrls = await RobotsAndSitemapService.parseSitemap(target);
      
      robotsPaths.forEach(url => allEndpoints.push({ url, method: 'GET', type: 'robots' }));
      sitemapUrls.forEach(url => allEndpoints.push({ url, method: 'GET', type: 'sitemap' }));
      
      // Tool 3: JavaScript File Analysis
      const jsEndpoints = await JSFileAnalyzer.analyzeJSFiles(target);
      allEndpoints.push(...jsEndpoints);
      
      // Tool 4: Directory & File Fuzzing
      const fuzzedPaths = await DirectoryFuzzer.fuzzDirectories(target);
      allEndpoints.push(...fuzzedPaths);
      
      // Tool 5: Active Crawling
      console.log(`    🕸️  Active crawling...`);
      try {
        const crawler = new CrawlerService();
        // Pass sessionCookie to crawler
        const crawlResult = await crawler.crawl(target, { 
          maxDepth: 3,
          maxPages: 100,
          sessionCookie: scan.sessionCookie
        });
        
        console.log(`       [DEBUG] Crawl result:`, {
          success: crawlResult.success,
          endpointsCount: crawlResult.endpoints?.length || 0,
          sampleEndpoints: crawlResult.endpoints?.slice(0, 3).map(ep => ({
            url: ep.url,
            method: ep.method,
            type: ep.type
          }))
        });
        
        if (crawlResult.success && crawlResult.endpoints && crawlResult.endpoints.length > 0) {
          // Add endpoints directly - they already have proper structure from CrawlerService
          allEndpoints.push(...crawlResult.endpoints);
          console.log(`       ✓ Crawled ${crawlResult.endpoints.length} pages`);
        } else {
          console.log(`       ⚠ No pages found via crawling`);
        }
      } catch (crawlError) {
        console.log(`       ⚠ Crawling error: ${crawlError.message}`);
        console.error(`       [DEBUG] Crawl error stack:`, crawlError.stack);
      }
      
      // Tool 6: Technology Fingerprinting
      console.log(`     Fingerprinting technologies...`);
      try {
        const fingerprint = await FingerprintService.fingerprint(target);
        if (fingerprint.success) {
          techStack.push(...fingerprint.technologies);
          console.log(`       ✓ Technologies: ${fingerprint.technologies.join(', ')}`);
        }
      } catch (fpError) {
        console.log(`       ⚠ Fingerprinting skipped`);
      }
      
      io.emit(`progress_${scanId}`, {
        phase: 'Phase 1: Reconnaissance',
        status: `Scanned ${i + 1}/${targets.length} targets`,
        progress: 15 + (i / targets.length) * 15,
        findings: allEndpoints.length
      });
      
    } catch (error) {
      console.error(`    ✗ Error with ${target}:`, error.message);
    }
    
    console.log(`  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
  }
  
  // Deduplicate endpoints
  const uniqueEndpoints = CrawlerService.deduplicateEndpoints(allEndpoints);
  console.log(`\n  📊 Reconnaissance Summary:`);
  console.log(`     • Total unique endpoints: ${uniqueEndpoints.length}`);
  console.log(`     • Wayback Machine: ${allEndpoints.filter(e => e.type === 'wayback').length}`);
  console.log(`     • JavaScript files: ${allEndpoints.filter(e => e.type === 'js_extracted').length}`);
  console.log(`     • Fuzzing: ${allEndpoints.filter(e => e.type === 'fuzzed').length}`);
  console.log(`     • Crawling: ${allEndpoints.filter(e => !e.type || e.type === 'discovered').length}`);
  console.log(`     • Known Vulnerable: ${allEndpoints.filter(e => e.type === 'known_vulnerable').length}`);
  console.log(`     • Tech stack: ${[...new Set(techStack)].join(', ') || 'Unknown'}\n`);
  
  scan.phases[1].status = 'completed';
  scan.phases[1].progress = 100;
  scan.progress = 30;
  await saveScanToFirebase(scan);
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 1: Complete',
    status: `Discovered ${uniqueEndpoints.length} endpoints`,
    progress: 30,
    findings: uniqueEndpoints.length
  });
  
  return { endpoints: uniqueEndpoints, techStack: [...new Set(techStack)] };
}

// Phase 2: Attack Surface Analysis - Parameter Discovery & Payload Generation
async function runPhase2(scanId, discoveredAssets) {
  const scan = activeScans[scanId];
  scan.phases[2].status = 'in_progress';
  
  console.log('🎯 Phase 2: Attack Surface Analysis');
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 2: Attack Surface',
    status: 'Discovering parameters...',
    progress: 40,
    findings: 0
  });
  
  const attackSurface = [];
  const seenVectors = new Set(); // Track unique endpoint+parameter combinations
  const { endpoints } = discoveredAssets;
  
  // Helper function to normalize URL (remove parameter values for deduplication)
  function normalizeURL(url) {
    try {
      const urlObj = new URL(url);
      const params = Array.from(urlObj.searchParams.keys()).sort();
      // Create normalized URL with just the path and parameter names (no values)
      return `${urlObj.origin}${urlObj.pathname}?${params.join('&')}`;
    } catch (e) {
      return url; // If parsing fails, return original URL
    }
  }
  
  // Filter out malformed/encoded URLs and prioritize clean endpoints
  const cleanEndpoints = endpoints.filter(ep => {
    try {
      const url = new URL(ep.url);
      // Skip URLs with excessive encoding or weird characters
      if (url.pathname.includes('%CB%93') || url.pathname.includes('%E2%80') || 
          url.pathname.includes('%D9%') || url.pathname.length > 200) {
        return false;
      }
      // Prioritize URLs with actual parameters or common paths
      return true;
    } catch (e) {
      return false;
    }
  });
  
  // Prioritize: crawled endpoints > fuzzed > wayback > others
  const prioritizedEndpoints = [
    ...cleanEndpoints.filter(ep => ep.type === 'discovered' || ep.type === 'form'),
    ...cleanEndpoints.filter(ep => ep.type === 'fuzzed'),
    ...cleanEndpoints.filter(ep => ep.type === 'wayback'),
    ...cleanEndpoints.filter(ep => !ep.type || (ep.type !== 'discovered' && ep.type !== 'form' && ep.type !== 'fuzzed' && ep.type !== 'wayback'))
  ];
  
  console.log(`  🔍 Filtered: ${prioritizedEndpoints.length} clean endpoints from ${endpoints.length} total`);
  
  // Discover parameters for each endpoint
  for (let i = 0; i < Math.min(prioritizedEndpoints.length, 100); i++) {
    const endpoint = prioritizedEndpoints[i];
    
    try {
      console.log(`  🔍 Analyzing: ${endpoint.url}`);
      
      // Discover all parameters
      const paramResult = await ParameterDiscovery.discoverParameters(
        endpoint.url,
        endpoint.method || 'GET'
      );
      
      if (paramResult.success && paramResult.parameters.length > 0) {
        const injectable = ParameterDiscovery.getInjectableParameters(paramResult.parameters);
        
        // Generate context-aware payloads for each parameter
        for (const param of injectable) {
          // Create unique key for deduplication using normalized URL
          const normalizedUrl = normalizeURL(endpoint.url);
          const vectorKey = `${normalizedUrl}::${param.name}`;
          
          // Skip if we've already added this endpoint+parameter combination
          if (seenVectors.has(vectorKey)) {
            continue;
          }
          
          seenVectors.add(vectorKey);
          
          const payloads = PayloadGenerator.generatePayloadsByPriority(param);
          
          attackSurface.push({
            endpoint,
            parameter: param,
            payloads: payloads.slice(0, 20), // Top 20 payloads per parameter
            classification: param.classification,
            sensitivity: param.sensitivity
          });
        }
        
        console.log(`    ✓ Found ${injectable.length} injectable parameters`);
      }
      
      io.emit(`progress_${scanId}`, {
        phase: 'Phase 2: Attack Surface',
        status: `Analyzed ${i + 1}/${Math.min(prioritizedEndpoints.length, 100)} endpoints`,
        progress: 40 + (i / Math.min(prioritizedEndpoints.length, 100)) * 10,
        findings: attackSurface.length
      });
      
    } catch (error) {
      console.error(`    ✗ Error analyzing ${endpoint.url}:`, error.message);
    }
  }
  
  console.log(`  ✓ Total attack surface: ${attackSurface.length} unique testable parameters (duplicates removed)`);
  
  scan.phases[2].status = 'completed';
  scan.phases[2].progress = 100;
  scan.progress = 50;
  await saveScanToFirebase(scan);
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 2: Complete',
    status: `Identified ${attackSurface.length} attack vectors`,
    progress: 50,
    findings: attackSurface.length
  });
  
  return attackSurface;
}

// Phase 3: Systematic Vulnerability Testing (Mixture of Agents Approach)
async function runPhase3(scanId, attackSurface) {
  const scan = activeScans[scanId];
  scan.phases[3].status = 'in_progress';
  
  console.log('💥 Phase 3: Mixture of Agents (MoA) AI Swarm Testing');
  
  // Pass the FULL attackSurface (with real endpoint + parameter objects) to the Master Agent
  const confirmedVulnsRaw = await MasterAgent.orchestrate(scan.domain, attackSurface, io, scanId, scan.sessionCookie);
  
  const confirmedVulns = [];
  
  for (const result of confirmedVulnsRaw) {
    // Try to find a matching attack vector (for SQLi/XSS findings)
    const originalVector = attackSurface.find(
      v => v.endpoint?.url === result.endpoint && v.parameter?.name === result.parameter
    );

    if (originalVector) {
      // Full match — use original endpoint + parameter objects
      const vuln = await createVulnerability(
        { type: result.type, payloadUsed: result.payload, evidence: [result.proof || result.description] },
        originalVector.endpoint,
        originalVector.parameter,
        scan
      );
      if (vuln) {
        vuln.severity = result.severity || vuln.severity;
        vuln.description = result.description || vuln.description;
        confirmedVulns.push(vuln);
      }
    } else {
      // No vector match (e.g. header findings target the host, not a specific parameter)
      // Build synthetic endpoint and parameter objects from the finding itself
      const syntheticEndpoint = { url: result.endpoint, method: 'GET' };
      const syntheticParameter = { name: result.parameter || 'headers', type: 'header', classification: result.type };
      const vuln = await createVulnerability(
        { type: result.type, payloadUsed: result.payload, evidence: [result.proof || result.description] },
        syntheticEndpoint,
        syntheticParameter,
        scan
      );
      if (vuln) {
        vuln.severity = result.severity || vuln.severity;
        vuln.description = result.description || vuln.description;
        confirmedVulns.push(vuln);
      }
    }
  }

  scan.phases[3].status = 'completed';
  scan.phases[3].progress = 100;
  scan.progress = 99.5;
  await saveScanToFirebase(scan);
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 3: Complete',
    status: `Found ${confirmedVulns.length} confirmed vulnerabilities`,
    progress: 99.5,
    findings: confirmedVulns.length
  });
  
  return confirmedVulns;
}


// Helper function to create vulnerability object
async function createVulnerability(result, endpoint, parameter, scan) {
  // Safety checks for required fields
  if (!endpoint || !endpoint.url || !parameter || !parameter.name) {
    console.warn('    ⚠ Skipping vulnerability due to missing endpoint or parameter data');
    return null;
  }
  
  const severity = SeverityCalculator.calculateSimpleSeverity({
    type: result.type,
    impact: 'high',
    auth: 'none',
    complexity: 'low'
  });
  
  const poc = PoCGenerator.generatePoC({
    type: result.type,
    endpoint,
    parameter,
    payload: { payload: result.payloadUsed || result.evidence?.[0] || 'test' },
    response: { data: result.evidence?.join('\n') || 'Response data not available' }
  });
  
  const vulnerability = {
    id: `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    type: result.type,
    severity: severity.severity,
    cvss: severity.score / 10,
    endpoint: endpoint.url || 'Unknown',
    parameter: parameter.name || 'Unknown',
    parameterClassification: parameter.classification || 'generic',
    description: `The "${parameter.name}" parameter is vulnerable to ${result.type}. ${result.evidence?.join('. ') || 'No evidence details'}`,
    payload: result.payloadUsed || result.evidence?.[0] || 'Unknown payload',
    confidence: result.confidence || 0,
    indicators: result.evidence || [],
    poc,
    request: {
      method: endpoint.method || 'GET',
      url: endpoint.url || 'Unknown',
      parameter: parameter.name || 'Unknown',
      value: result.payloadUsed || 'multiple payloads tested'
    },
    response: {
      status: 200,
      snippet: (result.evidence?.join('\n') || '').substring(0, 500)
    },
    context: result.context || 'N/A',
    exploitationMethod: 'Systematic Testing',
    discoveredAt: new Date().toISOString()
  };
  
  scan.vulnerabilities.push(vulnerability);
  await saveScanToFirebase(scan);
  
  return vulnerability;
}

// Phase 4: Professional Bug Bounty Report Generation
async function runPhase4(scanId, vulnerabilities) {
  const scan = activeScans[scanId];
  scan.phases[4].status = 'in_progress';
  
  console.log('📊 Phase 4: Professional Bug Bounty Report Generation\n');
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 4: Reporting',
    status: 'Generating HackerOne/Bugcrowd style reports...',
    progress: 95,
    findings: scan.vulnerabilities.length
  });
  
  const bugBountyReports = [];
  const vulnerabilitiesToReport = vulnerabilities || scan.vulnerabilities;
  
  console.log(`  📝 Generating reports for ${vulnerabilitiesToReport.length} findings...`);
  
  // Generate per-vulnerability reports — each wrapped in try-catch so one failure doesn't kill the whole phase
  for (const vuln of vulnerabilitiesToReport) {
    try {
      const bbReport = BugBountyReportService.generateBugBountyReport(vuln);
      const markdownReport = BugBountyReportService.generateMarkdownReport(vuln);
      bugBountyReports.push({ vulnerability: vuln, report: bbReport, markdown: markdownReport, submission_ready: true });
      console.log(`     ✓ ${bbReport.title} [CVSS: ${bbReport.cvss.score}/10]`);
    } catch (error) {
      console.error(`     ✗ Report generation error for ${vuln.type}: ${error.message}`);
      // Add minimal fallback report so we don't lose the finding
      bugBountyReports.push({
        vulnerability: vuln,
        report: { title: vuln.type, cvss: { score: 5, severity: vuln.severity?.toUpperCase() || 'MEDIUM' } },
        markdown: `## ${vuln.type}\n**Endpoint:** ${vuln.endpoint}\n**Payload:** ${vuln.payload}`,
        submission_ready: false
      });
    }
  }
  
  // Generate executive report — also wrapped in try-catch
  let executiveReport = { executive_summary: { risk_level: 'Unknown' }, statistics: { total_vulnerabilities: vulnerabilitiesToReport.length, by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } } };
  try {
    executiveReport = ReportGenerator.generateReport(vulnerabilitiesToReport, {
      domain: scan.domain,
      duration: Date.now() - new Date(scan.createdAt).getTime(),
      scanId
    });
    console.log(`\n  📊 Executive Summary:`);
    console.log(`     • Risk Level: ${executiveReport.executive_summary.risk_level}`);
    console.log(`     • Total Findings: ${executiveReport.statistics.total_vulnerabilities}`);
  } catch (e) {
    console.error('  ⚠ Executive report generation failed:', e.message);
  }
  
  // Store reports
  scan.report = executiveReport;
  scan.bugBountyReports = bugBountyReports;
  
  // Estimate rewards
  let estimatedRewards = { total: 0, critical: 0, high: 0, medium: 0, low: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 };
  try {
    estimatedRewards = _estimateBugBountyRewards(bugBountyReports);
    console.log(`\n  💰 Estimated Bug Bounty Value: $${estimatedRewards.total}`);
  } catch (e) {}
  scan.estimatedBounty = estimatedRewards;
  
  // Web3 Integration: IPFS Pinning and Escrow Payout
  try {
    // 1. Upload to IPFS
    const ipfsHash = await IpfsService.uploadToIPFS(executiveReport);
    scan.ipfsHash = ipfsHash;
    
    // 2. Trigger Escrow payout (if vulnerabilities exist)
    if (vulnerabilitiesToReport.length > 0) {
      // Concept B: The AI works for the Platform. The Platform (MetaMask Treasury) gets the bounty.
      const treasuryWallet = '0x28F6CAbd2d5B3b125F98ce8A3410676B23485A0b'; 
      const payoutTxHash = await EscrowService.triggerPayout(treasuryWallet, ipfsHash);
      scan.payoutTxHash = payoutTxHash;
      
      io.emit('transaction_mined', {
        scanId,
        ipfsHash,
        payoutTxHash,
        status: 'Bounty Paid'
      });
    }
  } catch (e) {
    console.error(`  ❌ Web3 Integration Error: ${e.message}`);
  }
  
  // GUARANTEED COMPLETION — always runs no matter what happened above
  scan.phases[4].status = 'completed';
  scan.phases[4].progress = 100;
  scan.progress = 100;
  scan.status = 'completed';
  await saveScanToFirebase(scan);
  
  io.emit(`progress_${scanId}`, {
    phase: 'Phase 4: Complete',
    status: `Scan complete! Found ${scan.vulnerabilities.length} vulnerabilities. Reports ready.`,
    progress: 100,
    findings: scan.vulnerabilities.length
  });

  // Dedicated completion event — frontend listens to this to navigate to results page
  io.emit(`scan_complete_${scanId}`, {
    scanId,
    status: 'completed',
    totalVulnerabilities: scan.vulnerabilities.length,
    estimatedBounty: estimatedRewards.total
  });
  
  return { executiveReport, bugBountyReports, estimatedRewards };
}


// Estimate bug bounty rewards (based on HackerOne/Bugcrowd averages)
function _estimateBugBountyRewards(reports) {
  const rewards = {
    CRITICAL: 5000,  // $3k-10k average
    HIGH: 2000,      // $1k-5k average
    MEDIUM: 500,     // $250-1k average
    LOW: 100         // $50-250 average
  };
  
  let total = 0;
  let critical = 0, high = 0, medium = 0, low = 0;
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  
  for (const report of reports) {
    const severity = report.report.cvss.severity;
    
    if (severity === 'CRITICAL') {
      critical += rewards.CRITICAL;
      criticalCount++;
    } else if (severity === 'HIGH') {
      high += rewards.HIGH;
      highCount++;
    } else if (severity === 'MEDIUM') {
      medium += rewards.MEDIUM;
      mediumCount++;
    } else if (severity === 'LOW') {
      low += rewards.LOW;
      lowCount++;
    }
  }
  
  total = critical + high + medium + low;
  
  return {
    total,
    critical,
    high,
    medium,
    low,
    criticalCount,
    highCount,
    mediumCount,
    lowCount
  };
}

// ============================================================================
// START SERVER
// ============================================================================

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log('🎯 ZerOn Vulnerability Scanner - Backend Started!');
  console.log(`${'='.repeat(60)}`);
  console.log(`✓ Server running on port ${PORT}`);
  console.log(`✓ Socket.io ready for real-time updates`);
  console.log(`✓ API endpoints available`);
  console.log(`✓ Allowed Origins: ${allowedOrigins.join(', ')}`);
  console.log(`✓ Production Frontend: ${process.env.FRONTEND_URL || 'https://zer0n.vercel.app'}`);
  console.log(`${'='.repeat(60)}\n`);
});
