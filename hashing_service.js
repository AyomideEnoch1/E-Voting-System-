/**
 * HashingService
 * - bcrypt password hashing (salt rounds: 12)
 * - SHA-256 / configurable data hashing
 * - HMAC generation & constant-time verification
 */

const bcrypt = require('bcrypt');
const crypto = require('crypto');

class HashingService {
  constructor() {
    this.saltRounds = 12;
  }

  /** Hash password using bcrypt with salt */
  async hashPassword(password) {
    try {
      const salt = await bcrypt.genSalt(this.saltRounds);
      return await bcrypt.hash(password, salt);
    } catch {
      throw new Error('Password hashing failed');
    }
  }

  /** Verify password against stored bcrypt hash */
  async verifyPassword(password, hash) {
    try {
      return await bcrypt.compare(password, hash);
    } catch {
      throw new Error('Password verification failed');
    }
  }

  /** SHA-256 (or configurable algorithm) hash for data integrity */
  hashData(data, algorithm = 'sha256') {
    return crypto.createHash(algorithm).update(String(data)).digest('hex');
  }

  /** Generate HMAC-SHA256 signature */
  generateHMAC(key, data) {
    return crypto.createHmac('sha256', key).update(String(data)).digest('hex');
  }

  /** Verify HMAC using constant-time comparison (prevents timing attacks) */
  verifyHMAC(key, data, signature) {
    const computed = this.generateHMAC(key, data);
    if (computed.length !== signature.length) return false;
    return crypto.timingSafeEqual(
      Buffer.from(computed),
      Buffer.from(signature)
    );
  }

  /** Generate a cryptographically secure random token */
  generateSecureToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
  }

  /** Hash vote for anonymized audit trail (SHA-256 of voterId + candidateId + salt) */
  hashVoteRecord(voterId, candidateId, electionId, salt) {
    const data = `${voterId}:${candidateId}:${electionId}:${salt}`;
    return this.hashData(data);
  }
}

module.exports = new HashingService();
