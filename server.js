require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 8080;

const admin = require('firebase-admin');
const serviceAccount = require(process.env.FIREBASE_KEY_PATH || './firebase-key.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

const ALGORITHM = 'aes-256-gcm';
const KEY = Buffer.from(process.env.ENCRYPTION_SECRET, 'hex');

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encrypted, iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex') };
}

function decrypt(encrypted, iv, authTag) {
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

app.use(express.json());
app.use(express.static('static'));

const PROVIDER_URL = 'https://ninbvnportal.com.ng/api/nin-verification';

async function requireTenant(req, res, next) {
  const licenseKey = (req.headers['x-license-key'] || '').trim();
  if (!licenseKey) return res.status(401).json({ error: 'License key required' });

  try {
    const hash = crypto.createHash('sha256').update(licenseKey).digest('hex');
    const snap = await db.collection('tenants').where('licenseKeyHash', '==', hash).limit(1).get();
    if (snap.empty) return res.status(401).json({ error: 'Invalid license key' });

    const doc = snap.docs[0];
    const tenant = { tenantId: doc.id, ...doc.data() };

    if (tenant.status !== 'active') return res.status(403).json({ error: 'License not active' });
    if (tenant.expiresAt?.toDate() < new Date()) return res.status(403).json({ error: 'License expired' });
    if (!tenant.providerApiKeyEncrypted) return res.status(403).json({ error: 'Kiosk not activated. Run setup first.' });

    tenant.decryptedProviderKey = decrypt(tenant.providerApiKeyEncrypted, tenant.providerApiKeyIv, tenant.providerApiKeyAuthTag);
    req.tenant = tenant;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
}

app.post('/api/setup', async (req, res) => {
  const licenseKey = (req.body.licenseKey || '').trim();
  const providerApiKey = (req.body.providerApiKey || '').trim();
  if (!licenseKey || !providerApiKey) {
    return res.status(400).json({ error: 'License key and provider API key required' });
  }

  try {
    const hash = crypto.createHash('sha256').update(licenseKey).digest('hex');
    const snap = await db.collection('tenants')
      .where('licenseKeyHash', '==', hash)
      .limit(1)
      .get();

    if (snap.empty) return res.status(404).json({ error: 'Invalid license key' });

    const doc = snap.docs[0];
    const currentStatus = doc.data().status;

    // Allow both first activation AND reactivation
    if (currentStatus !== 'pending_setup' && currentStatus !== 'active') {
      return res.status(400).json({ error: 'License is suspended or expired' });
    }

    const enc = encrypt(providerApiKey);
    await doc.ref.update({
      providerApiKeyEncrypted: enc.encrypted,
      providerApiKeyIv: enc.iv,
      providerApiKeyAuthTag: enc.authTag,
      status: 'active',
      reactivatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, reactivated: currentStatus === 'active' });
  } catch (err) {
    console.error('Setup error:', err);
    res.status(500).json({ error: 'Setup failed' });
  }
});

app.post('/api/lookup', requireTenant, async (req, res) => {
  const { nin, consent, demo } = req.body;

  if (demo === true) {
    return res.json({
      firstname: 'CHUKWUEMEKA', surname: 'ADEBOWALE', middlename: 'JAMES',
      fullname: 'CHUKWUEMEKA JAMES ADEBOWALE', photo: '', signature: '',
      birthdate: '1995-06-12', gender: 'M', phone: '08012345678',
      maritalstatus: 'Single', birthstate: 'Lagos', birthlga: 'Ikeja',
      address: '12 Broad Street, Lagos Island, Lagos', nin
    });
  }

  if (!nin || !/^\d{11}$/.test(nin)) return res.status(400).json({ error: 'Invalid NIN — exactly 11 digits required' });
  if (consent !== true) return res.status(400).json({ error: 'User consent is required' });

  try {
    const response = await fetch(PROVIDER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': req.tenant.decryptedProviderKey },
      body: JSON.stringify({ nin, consent: true }),
    });

    const data = await response.json();
    if (!response.ok || data.status !== 'success') return res.status(400).json({ error: data.message || 'Verification failed' });

    const d = data.data?.data;
    if (!d) return res.status(500).json({ error: 'Unexpected response structure' });

    const fullname = [d.firstname, d.middlename, d.surname].filter(Boolean).join(' ').toUpperCase();
    const addressParts = [d.residence_address, d.residence_town, d.residence_state].filter(Boolean);
    const address = addressParts.length ? addressParts.join(', ') : '';

    // ─── Save metadata ONLY (zero PII) ─────────────────────
    await db.collection('usage').add({
      tenantId: req.tenant.tenantId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      success: true,
      providerCostKobo: 15000,
      clientIp: req.ip,
      consentRecorded: true,
      userAgent: req.headers['user-agent']?.slice(0, 100) || ''
    });

    await db.collection('tenants').doc(req.tenant.tenantId).update({
      lookupCountThisMonth: admin.firestore.FieldValue.increment(1)
    });

    res.json({
      firstname: d.firstname || '', surname: d.surname || '', middlename: d.middlename || '',
      fullname, photo: d.photo || '', signature: d.signature || '',
      birthdate: d.birthdate || '', gender: d.gender || '',
      phone: d.telephoneno || d.phone || '', maritalstatus: d.maritalstatus || '',
      birthstate: d.birthstate || '', birthlga: d.birthlga || '', address, nin
    });
  } catch (err) {
    console.error('Provider error:', err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/api/tenant', requireTenant, (req, res) => {
  const t = req.tenant;
  res.json({
    cafeName: t.cafeName, status: t.status,
    expiresAt: t.expiresAt?.toDate?.()?.toISOString() || null,
    lookupCountThisMonth: t.lookupCountThisMonth || 0,
    tier: t.tier || 'basic'
  });
});

app.get('/api/usage', requireTenant, async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);

  try {
    const snap = await db.collection('usage')
      .where('tenantId', '==', req.tenant.tenantId)
      .where('timestamp', '>=', admin.firestore.Timestamp.fromDate(cutoff))
      .orderBy('timestamp', 'desc')
      .get();

    const total = snap.size;
    const successful = snap.docs.filter(d => d.data().success).length;
    const daily = {};
    snap.docs.forEach(doc => {
      const d = doc.data().timestamp.toDate().toISOString().split('T')[0];
      daily[d] = (daily[d] || 0) + 1;
    });

    res.json({ total, successful, failed: total - successful, daily, periodDays: days });
  } catch (err) {
    console.error('Usage error:', err);
    res.status(500).json({ error: 'Could not load usage' });
  }
});


// ══════════════════════════════════════════════════════════
//  POST /api/bvn  –  Verify BVN (tenant-scoped)
// ══════════════════════════════════════════════════════════
const BVN_PROVIDER_URL = 'https://checkmyninbvn.com.ng/api/bvn-verification';

app.post('/api/bvn', requireTenant, async (req, res) => {
  const { bvn, consent, demo } = req.body;

  if (demo === true) {
    return res.json({
      firstname: 'JOHN', middlename: 'OLUMIDE', lastname: 'ADEBAYO',
      fullname: 'JOHN OLUMIDE ADEBAYO', phone: '08012345678',
      email: 'john.adebayo@email.com', bvn: '22350591353',
      dob: '15-May-90', gender: 'Male', state_of_origin: 'Ogun',
      state_of_residence: 'Lagos', nationality: 'Nigerian',
      photo: ''
    });
  }

  if (!bvn || !/^\d{11}$/.test(bvn)) return res.status(400).json({ error: 'Invalid BVN — exactly 11 digits required' });
  if (consent !== true) return res.status(400).json({ error: 'User consent is required' });

  try {
    const response = await fetch(BVN_PROVIDER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': req.tenant.decryptedProviderKey },
      body: JSON.stringify({ bvn, consent: true }),
    });

    const data = await response.json();
    console.log('BVN provider raw response:', JSON.stringify(data));
    if (!response.ok || data.status !== 'success') {
      return res.status(400).json({ error: data.message || data.error || 'BVN verification failed', _providerStatus: response.status });
    }

    const d = data.data;
    if (!d) return res.status(500).json({ error: 'Unexpected response structure', _raw: data });

    const fullname = [d.firstname, d.middlename, d.lastname].filter(Boolean).join(' ').toUpperCase();

    await db.collection('usage').add({
      tenantId: req.tenant.tenantId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      success: true,
      providerCostKobo: 15000,
      clientIp: req.ip,
      consentRecorded: true,
      userAgent: req.headers['user-agent']?.slice(0, 100) || '',
      serviceType: 'bvn'
    });

    await db.collection('tenants').doc(req.tenant.tenantId).update({
      lookupCountThisMonth: admin.firestore.FieldValue.increment(1)
    });

    res.json({
      firstname: d.firstname || '',
      lastname: d.lastname || '',
      middlename: d.middlename || '',
      fullname,
      phone: d.phone || '',
      email: d.email || '',
      bvn: d.bvn || '',
      dob: d.dob || '',
      gender: d.gender || '',
      state_of_origin: d.state_of_origin || '',
      state_of_residence: d.state_of_residence || '',
      nationality: d.nationality || '',
      photo: d.photo || ''
    });
  } catch (err) {
    console.error('BVN provider error:', err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});





app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
