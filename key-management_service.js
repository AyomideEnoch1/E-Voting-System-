const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

class KeyManagementService {
  constructor() {
    this.keys      = new Map();
    this.keyExpiry = 24 * 60 * 60 * 1000;
    if (!process.env.JWT_SECRET) {
      console.error('FATAL: JWT_SECRET not set in .env — set it and restart.');
      process.exit(1);
    }
    this.jwtSecret = process.env.JWT_SECRET;
  }

  generateRSAKeyPair() {
    const passphrase = process.env.KEY_PASSPHRASE || '';
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
    });
    return { publicKey, privateKey };
  }

  generateECDSAKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
  }

  generateElectionKey() { return crypto.randomBytes(32).toString('hex'); }

  storeKey(keyId, keyData) {
    this.keys.set(keyId, { data: keyData, createdAt: Date.now(), expiresAt: Date.now() + this.keyExpiry });
  }

  getKey(keyId) {
    const entry = this.keys.get(keyId);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { this.keys.delete(keyId); return null; }
    return entry.data;
  }

  generateToken(payload, expiresIn = process.env.JWT_EXPIRES || '8h') {
    return jwt.sign(payload, this.jwtSecret, { expiresIn });
  }

  verifyToken(token) {
    try { return jwt.verify(token, this.jwtSecret); }
    catch { throw new Error('Invalid or expired token'); }
  }

  purgeExpiredKeys() {
    const now = Date.now();
    for (const [id, entry] of this.keys.entries()) {
      if (now > entry.expiresAt) this.keys.delete(id);
    }
  }
}

module.exports = new KeyManagementService();
