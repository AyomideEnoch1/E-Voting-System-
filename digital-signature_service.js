/**
 * DigitalSignatureService
 * - RSA-SHA256 sign & verify (for ballot integrity)
 * - HMAC-SHA256 generation
 * - Vote receipt signing (proves vote was cast without revealing choice)
 */

const crypto = require('crypto');

class DigitalSignatureService {

  /**
   * Sign data with RSA private key (SHA-256)
   * Used to sign ballot receipts and election results
   */
  signData(data, privateKey, passphrase = process.env.KEY_PASSPHRASE || '') {
    try {
      const sign = crypto.createSign('SHA256');
      sign.update(String(data));
      sign.end();
      return sign.sign({ key: privateKey, passphrase }, 'hex');
    } catch {
      throw new Error('Signing failed');
    }
  }

  /**
   * Verify signature with RSA public key
   * Used to verify ballot & result authenticity
   */
  verifySignature(data, signature, publicKey) {
    try {
      const verify = crypto.createVerify('SHA256');
      verify.update(String(data));
      verify.end();
      return verify.verify(publicKey, signature, 'hex');
    } catch {
      throw new Error('Signature verification failed');
    }
  }

  /** HMAC-SHA256 for message authentication */
  generateHMAC(key, data) {
    return crypto.createHmac('sha256', key).update(String(data)).digest('hex');
  }

  /**
   * Generate a signed vote receipt
   * Voter gets proof they voted — without revealing their choice
   * Receipt = signed hash of (voterId + electionId + timestamp + nonce)
   */
  generateVoteReceipt(voterId, electionId, privateKey) {
    const nonce     = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const receiptData = JSON.stringify({ voterId, electionId, timestamp, nonce });
    const signature = this.signData(receiptData, privateKey);
    return {
      receiptData,
      signature,
      receiptHash: crypto.createHash('sha256').update(receiptData).digest('hex')
    };
  }

  /**
   * Verify a vote receipt is authentic
   */
  verifyVoteReceipt(receiptData, signature, publicKey) {
    return this.verifySignature(receiptData, signature, publicKey);
  }

  /**
   * Sign election results (admin signs final tally)
   * Provides non-repudiation for published results
   */
  signElectionResults(results, privateKey) {
    const data = JSON.stringify(results);
    const signature = this.signData(data, privateKey);
    return { data, signature };
  }
}

module.exports = new DigitalSignatureService();
