require('dotenv').config({ path: '../.env' });
const crypto = require('crypto');
const admin = require('firebase-admin');

const serviceAccount = require(process.env.FIREBASE_KEY_PATH || '../firebase-key.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

function generateLicenseKey(prefix = 'CAFE') {
  const date = new Date().toISOString().slice(2, 4);
  const random = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${prefix}-${date}-${random}`;
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

async function createTenant() {
  const cafeName = process.argv[2] || 'Unnamed Cafe';
  const adminPhone = process.argv[3] || '08000000000';
  const tier = process.argv[4] || 'basic';
  const monthsValid = parseInt(process.argv[5]) || 6;

  const licenseKey = generateLicenseKey();
  const licenseKeyHash = sha256(licenseKey);

  const expiresAt = new Date();
  expiresAt.setMonth(expiresAt.getMonth() + monthsValid);

  const tenantData = {
    cafeName,
    adminPhone,
    licenseKeyHash,
    status: 'pending_setup',
    tier,
    maxTerminals: tier === 'pro' ? 5 : 2,
    lookupCountThisMonth: 0,
    expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  };

  const docRef = await db.collection('tenants').add(tenantData);

  console.log('\n✅ Tenant created successfully\n');
  console.log('Firestore ID:', docRef.id);
  console.log('Cafe Name:', cafeName);
  console.log('Phone:', adminPhone);
  console.log('Tier:', tier);
  console.log('Expires:', expiresAt.toISOString().split('T')[0]);
  console.log('\n🔑 SEND THIS LICENSE KEY TO THE CAFE OWNER:');
  console.log('   ', licenseKey);
  console.log('\n⚠️  Copy it now. It is NOT stored anywhere.\n');
}

createTenant().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
