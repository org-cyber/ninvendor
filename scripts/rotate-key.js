require('dotenv').config();
const crypto = require('crypto');
const admin = require('firebase-admin');

const OLD_SECRET = process.env.OLD_ENCRYPTION_SECRET; // set temporarily
const NEW_SECRET = process.env.ENCRYPTION_SECRET;

if (!OLD_SECRET || !NEW_SECRET) {
  console.error('Set both OLD_ENCRYPTION_SECRET and ENCRYPTION_SECRET');
  process.exit(1);
}

const OLD_KEY = Buffer.from(OLD_SECRET, 'hex');
const NEW_KEY = Buffer.from(NEW_SECRET, 'hex');

const serviceAccount = require(process.env.FIREBASE_KEY_PATH || '../firebase-key.json');
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

function oldDecrypt(encrypted, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', OLD_KEY, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  let d = decipher.update(encrypted, 'hex', 'utf8');
  d += decipher.final('utf8');
  return d;
}

function newEncrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', NEW_KEY, iv);
  let e = cipher.update(text, 'utf8', 'hex');
  e += cipher.final('hex');
  return {
    encrypted: e,
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex')
  };
}

async function rotate() {
  const snap = await db.collection('tenants')
    .where('providerApiKeyEncrypted', '!=', null)
    .get();

  let count = 0;
  for (const doc of snap.docs) {
    const d = doc.data();
    if (!d.providerApiKeyEncrypted) continue;

    try {
      const plain = oldDecrypt(d.providerApiKeyEncrypted, d.providerApiKeyIv, d.providerApiKeyAuthTag);
      const enc = newEncrypt(plain);

      await doc.ref.update({
        providerApiKeyEncrypted: enc.encrypted,
        providerApiKeyIv: enc.iv,
        providerApiKeyAuthTag: enc.authTag,
        keyRotatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      count++;
    } catch (e) {
      console.error(`Failed to rotate ${doc.id}:`, e.message);
    }
  }

  console.log(`\n🔁 Rotated ${count} tenant keys\n`);
  console.log('Unset OLD_ENCRYPTION_SECRET from .env immediately!');
}

rotate().catch(console.error);
