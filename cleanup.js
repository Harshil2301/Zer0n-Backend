require('dotenv').config();
const { db } = require('./config/firebase');

async function checkScans() {
  console.log('Checking scanreturn collection...');
  try {
    const scanRef = db.collection('scanreturn');
    const snapshot = await scanRef.get();
    
    if (snapshot.empty) {
      console.log('No matching documents.');
      return;
    }

    const accounts = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      const numScans = data.scanResults ? data.scanResults.length : 0;
      accounts.push({ id: doc.id, numScans });
    });

    accounts.sort((a, b) => b.numScans - a.numScans);
    
    console.log('--- Account Summary ---');
    accounts.forEach(acc => {
      console.log(`User ID: ${acc.id} | Total Scans: ${acc.numScans}`);
    });
    
    // Find duplicates (assuming they are the ones with < 13 scans if there's one with 13)
    const toKeep = accounts.find(a => a.numScans === 13) || accounts[0];
    console.log(`\nAccount to KEEP: ${toKeep.id} (${toKeep.numScans} scans)`);
    
    const toDelete = accounts.filter(a => a.id !== toKeep.id);
    console.log(`Accounts to DELETE:`, toDelete.map(a => a.id));
    
    for (const acc of toDelete) {
      console.log(`Deleting scanreturn for ${acc.id}...`);
      await db.collection('scanreturn').doc(acc.id).delete();
      
      console.log(`Deleting user profile for ${acc.id}...`);
      await db.collection('users').doc(acc.id).delete();
      
      // Also delete from faceVectors if userId matches
      const faceVectorsRef = db.collection('faceVectors');
      const faceSnap = await faceVectorsRef.where('userId', '==', acc.id).get();
      faceSnap.forEach(async (doc) => {
        console.log(`Deleting faceVector doc ${doc.id} for user ${acc.id}...`);
        await faceVectorsRef.doc(doc.id).delete();
      });
    }

    console.log('Cleanup complete!');
  } catch (error) {
    console.error('Error:', error);
  }
}

checkScans();
