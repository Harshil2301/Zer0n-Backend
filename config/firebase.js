// Firebase configuration and initialization
// This file is tolerant for local development: if no Firebase credentials are
// provided it will export a lightweight in-memory stub for `db` and `auth` so
// the server can still start. In production, set FIREBASE_CONFIG (JSON string)
// or FIREBASE_CREDENTIALS_PATH (path to service account JSON).

const admin = require('firebase-admin');
const path = require('path');

let useRealtimeFirebase = false;
let db; // will be assigned either to real firestore or a stub
let auth;

function createInMemoryFirestoreStub() {
  const store = {};

  function collection(name) {
    if (!store[name]) store[name] = {};

    return {
      doc: (id) => {
        return {
          set: async (data, opts) => {
            store[name][id] = Object.assign(store[name][id] || {}, data);
            return Promise.resolve();
          },
          get: async () => {
            const data = store[name][id] || null;
            return { exists: !!data, data: () => data };
          }
        };
      },
      // Very small query emulation for `.orderBy(...).limit(...).get()` used in server
      orderBy: function () {
        return {
          limit: function (n) {
            return {
              get: async () => {
                const items = Object.keys(store[name] || {}).map(id => ({ id, data: () => store[name][id] }));
                const limited = items.slice(0, n || items.length);
                return {
                  empty: limited.length === 0,
                  forEach: (fn) => limited.forEach(item => fn({ id: item.id, data: item.data })),
                  docs: limited
                };
              }
            };
          }
        };
      }
    };
  }

  return { collection };
}

function createAuthStub() {
  return {
    // Minimal stub: only methods used by this app should be implemented here.
    verifyIdToken: async (token) => {
      // In dev, accept any token and return a fake payload
      return { uid: 'dev-user', email: 'dev@local' };
    }
  };
}

// Load credentials from environment variables
let serviceAccount;
if (process.env.FIREBASE_CONFIG) {
  try {
    // Multi-stage cleaning to handle common cloud environment variable messes
    let rawConfig = process.env.FIREBASE_CONFIG.trim();
    
    // If it's wrapped in single quotes by the platform, remove them
    if (rawConfig.startsWith("'") && rawConfig.endsWith("'")) {
      rawConfig = rawConfig.slice(1, -1);
    }

    try {
      // First attempt: standard parse
      serviceAccount = JSON.parse(rawConfig);
    } catch (e) {
      // Second attempt: clean up common escaping issues
      // Convert literal newlines to \n characters
      const cleaned = rawConfig
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\\n/g, '\n'); // Code expects decoded newlines for private_key
      
      serviceAccount = JSON.parse(cleaned);
    }
    
    // Final check for private_key format
    if (serviceAccount.private_key) {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }
    
    useRealtimeFirebase = true;
    console.log('Using FIREBASE_CONFIG from environment variables.');
  } catch (error) {
    console.error('Failed to parse FIREBASE_CONFIG environment variable:', error.message);
    useRealtimeFirebase = false;
  }
} else if (process.env.FIREBASE_CREDENTIALS_PATH) {
  try {
    // allow relative paths
    const credentialsPath = path.isAbsolute(process.env.FIREBASE_CREDENTIALS_PATH)
      ? process.env.FIREBASE_CREDENTIALS_PATH
      : path.join(process.cwd(), process.env.FIREBASE_CREDENTIALS_PATH);

    serviceAccount = require(credentialsPath);
    useRealtimeFirebase = true;
    console.log('Using Firebase credentials from path:', credentialsPath);
  } catch (error) {
    console.error('Failed to load Firebase credentials from path:', error.message);
    useRealtimeFirebase = false;
  }
} else {
  // Try default location as last resort before stub
  try {
    const defaultPath = path.join(process.cwd(), 'config', 'firebase-credentials.json');
    serviceAccount = require(defaultPath);
    useRealtimeFirebase = true;
    console.log('Using Firebase credentials from default local path.');
  } catch (e) {
    console.warn('Firebase credentials not found in ENV or File. Using in-memory stub.');
    useRealtimeFirebase = false;
  }
}

const projectId = process.env.FIREBASE_PROJECT_ID || 'zeron-6b44c';

if (useRealtimeFirebase) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: projectId
    });

    db = admin.firestore();
    auth = admin.auth();
    console.log('Firebase admin initialized successfully.');
  } catch (err) {
    console.error('Failed to initialize Firebase admin:', err.message);
    console.error('Falling back to in-memory Firebase stub for local development.');
    db = createInMemoryFirestoreStub();
    auth = createAuthStub();
  }
} else {
  db = createInMemoryFirestoreStub();
  auth = createAuthStub();
}

module.exports = {
  admin: useRealtimeFirebase ? admin : null,
  db,
  auth
};
