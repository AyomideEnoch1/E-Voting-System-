const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const securityUtils = {
  generateId() { return uuidv4(); },

  generateSecureRandom(bytes = 32) { return crypto.randomBytes(bytes).toString('hex'); },

  anonymizeVoterId(voterId, electionId, secret) {
    return crypto.createHmac('sha256', secret).update(`${voterId}:${electionId}`).digest('hex');
  },

  sanitize(input) {
    if (typeof input !== 'string') return input;
    return input
      .replace(/<[^>]*>/g, '')
      .replace(/[<>"'&]/g, c => ({ '<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;','&':'&amp;' }[c]))
      .trim();
  },

  isValidVoterId(id) { return /^VTR-\d{6}$/.test(id); },

  hashIP(ip) { return crypto.createHash('sha256').update(ip || '').digest('hex').slice(0, 16); },

  // Constant-time comparison — prevents timing attacks on secret key comparison
  safeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const aLen = Buffer.byteLength(a);
    const bLen = Buffer.byteLength(b);
    const maxLen = Math.max(aLen, bLen);
    const aBuf = Buffer.alloc(maxLen);
    const bBuf = Buffer.alloc(maxLen);
    aBuf.write(a);
    bBuf.write(b);
    return crypto.timingSafeEqual(aBuf, bBuf) && aLen === bLen;
  }
};

// Alias so both secUtils.safeCompare and secUtils.constantTimeCompare work
securityUtils.constantTimeCompare = securityUtils.safeCompare;

module.exports = securityUtils;
