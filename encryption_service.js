/**
 * EncryptionService
 * - AES-256-GCM authenticated encryption for vote data
 * - PBKDF2 key derivation from passwords
 * - Random IV per encryption (prevents IV reuse attacks)
 */

const crypto = require('crypto');

class EncryptionService {
  constructor() {
    this.algorithm  = 'aes-256-gcm';
    this.ivLength   = 16;   // 128-bit IV
    this.saltLength = 64;   // 512-bit salt
    this.tagLength  = 16;   // 128-bit auth tag
    this.keyLength  = 32;   // 256-bit key
    this.iterations = 100000;
    this.digest     = 'sha256';
  }

  /** Generate a random AES-256 key */
  generateKey() {
    return crypto.randomBytes(this.keyLength);
  }

  /** Derive a deterministic key from a password using PBKDF2 */
  deriveKeyFromPassword(password, salt = null) {
    salt = salt || crypto.randomBytes(this.saltLength);
    const key = crypto.pbkdf2Sync(
      password, salt,
      this.iterations, this.keyLength, this.digest
    );
    return { key, salt };
  }

  /**
   * Encrypt data with AES-256-GCM
   * Returns: { encrypted, iv, tag, key } — all hex strings
   */
  encrypt(data, key = null) {
    try {
      key = key || this.generateKey();
      const iv     = crypto.randomBytes(this.ivLength);
      const cipher = crypto.createCipheriv(this.algorithm, key, iv);

      let encrypted = cipher.update(String(data), 'utf8', 'hex');
      encrypted    += cipher.final('hex');
      const tag     = cipher.getAuthTag();

      return {
        encrypted,
        iv:  iv.toString('hex'),
        tag: tag.toString('hex'),
        key: key.toString('hex')
      };
    } catch {
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt AES-256-GCM encrypted data
   * Auth tag verification prevents tampering
   */
  decrypt(encryptedData, key, iv, tag) {
    try {
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        Buffer.from(key, 'hex'),
        Buffer.from(iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(tag, 'hex'));

      let decrypted  = decipher.update(encryptedData, 'hex', 'utf8');
      decrypted     += decipher.final('utf8');
      return decrypted;
    } catch {
      throw new Error('Decryption failed — data may have been tampered with');
    }
  }

  /** Encrypt using a password (PBKDF2 + AES-256-GCM) */
  encryptWithPassword(data, password) {
    const { key, salt } = this.deriveKeyFromPassword(password);
    const result = this.encrypt(data, key);
    return {
      encrypted: result.encrypted,
      iv:        result.iv,
      tag:       result.tag,
      salt:      salt.toString('hex')
      // key intentionally omitted — never expose derived key
    };
  }

  /** Decrypt using a password */
  decryptWithPassword(encryptedData, password, salt, iv, tag) {
    const { key } = this.deriveKeyFromPassword(
      password, Buffer.from(salt, 'hex')
    );
    return this.decrypt(encryptedData, key.toString('hex'), iv, tag);
  }

  /**
   * Encrypt a vote choice — used to store votes anonymously
   * The election master key encrypts the actual candidate choice
   */
  encryptVote(candidateId, electionMasterKey) {
    return this.encrypt(String(candidateId), Buffer.from(electionMasterKey, 'hex'));
  }

  /** Decrypt a vote (only during official tally by admin) */
  decryptVote(encryptedVote, electionMasterKey) {
    return this.decrypt(
      encryptedVote.encrypted,
      electionMasterKey,
      encryptedVote.iv,
      encryptedVote.tag
    );
  }
}

module.exports = new EncryptionService();
