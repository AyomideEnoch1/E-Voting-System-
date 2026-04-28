const express            = require('express');
const router             = express.Router();
const { v4: uuid }       = require('uuid');
const hashingService     = require('./hashing_service');
const keyMgmt            = require('./key-management_service');
const authMiddleware     = require('./auth_middleware');
const { blacklistToken } = require('./auth_middleware');
const { authLimiter }    = require('./rate-limit_middleware');
const secUtils           = require('./security_utils');
const { parseMatric, isValidMatric } = require('./matric_utils');
const { q, q1 }          = require('./database');
const { sendVerificationEmail, sendVoterIdEmail, sendPasswordResetEmail } = require('./email_service');

const SCHOOL_DOMAIN      = '@run.edu.ng';
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_MS            = 15 * 60 * 1000;

async function generateVoterId() {
  let id, exists;
  do {
    id     = `VTR-${Math.floor(100000 + Math.random() * 900000)}`;
    exists = await q1('SELECT id FROM users WHERE voter_id=?', [id]);
  } while (exists);
  return id;
}

/* ── REGISTER ── */
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { full_name, email, password, matric_number, faculty } = req.body;
    if (!full_name || !email || !password)
      return res.status(400).json({ error: 'full_name, email and password are required' });
    if (full_name.trim().length < 2)
      return res.status(400).json({ error: 'Please provide your full name' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!email.toLowerCase().endsWith(SCHOOL_DOMAIN))
      return res.status(400).json({ error: `Only ${SCHOOL_DOMAIN} email addresses are allowed` });

    // Validate and parse matric number
    if (!matric_number)
      return res.status(400).json({ error: 'Matriculation number is required' });
    if (!isValidMatric(matric_number))
      return res.status(400).json({ error: 'Invalid matriculation number format. Expected: RUN/DEPT/YY/SERIAL (e.g. RUN/CYB/22/13123)' });

    const parsed = parseMatric(matric_number);

    // Faculty is still manually provided since it's not encoded in the matric
    if (!faculty || faculty.trim().length < 2)
      return res.status(400).json({ error: 'Please select your faculty' });

    if (await q1('SELECT id FROM users WHERE email=?', [email.toLowerCase()]))
      return res.status(400).json({ error: 'Email already registered' });
    if (await q1('SELECT id FROM users WHERE matric_number=?', [parsed.raw]))
      return res.status(400).json({ error: 'This matriculation number is already registered' });

    const id                = uuid();
    const password_hash     = await hashingService.hashPassword(password);
    const { publicKey }     = keyMgmt.generateECDSAKeyPair();
    const verificationToken = uuid();
    const tokenExpiry       = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await q(
      `INSERT INTO users
         (id, full_name, email, matric_number, dept_code, entry_year, serial_number, faculty,
          voter_id, password_hash, role, public_key, is_verified, verification_token, verification_token_expiry)
       VALUES (?,?,?,?,?,?,?,?,NULL,?,?,?,0,?,?)`,
      [id, secUtils.sanitize(full_name.trim()), email.toLowerCase(),
       parsed.raw, parsed.dept_code, parsed.entry_year, parsed.serial,
       secUtils.sanitize(faculty.trim()),
       password_hash, 'voter', publicKey, verificationToken, tokenExpiry]
    );
    await sendVerificationEmail(email.toLowerCase(), verificationToken, full_name.trim());
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'USER_REGISTERED', id, secUtils.hashIP(req.ip)]);

    res.status(201).json({ message: `Registration successful! A verification link has been sent to ${email}.` });
  } catch (e) {
    console.error('[REGISTER]', e);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

/* ── VERIFY EMAIL ── */
router.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Verification token is required' });

    const user = await q1('SELECT * FROM users WHERE verification_token=?', [token]);
    if (!user) return res.status(400).json({ error: 'Invalid or already used verification link' });

    if (user.is_verified) {
      await q('UPDATE users SET verification_token=NULL, verification_token_expiry=NULL WHERE id=?', [user.id]);
      return res.redirect(`/?verified=1&email=${encodeURIComponent(user.email)}`);
    }
    if (new Date(user.verification_token_expiry) < new Date()) {
      await q('UPDATE users SET verification_token=NULL, verification_token_expiry=NULL WHERE id=?', [user.id]);
      return res.status(400).json({ error: 'Verification link expired. Please register again.' });
    }

    const voterId = await generateVoterId();
    await q(
      `UPDATE users SET is_verified=1, voter_id=?, verification_token=NULL,
         verification_token_expiry=NULL WHERE id=? AND is_verified=0`,
      [voterId, user.id]
    );
    await sendVoterIdEmail(user.email, user.full_name, voterId);
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'EMAIL_VERIFIED', user.id, secUtils.hashIP(req.ip)]);

    res.redirect(`/?verified=1&email=${encodeURIComponent(user.email)}`);
  } catch (e) {
    console.error('[VERIFY EMAIL]', e);
    res.status(500).json({ error: 'Email verification failed.' });
  }
});

/* ── LOGIN ── */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const user = await q1('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
    if (!user) {
      await hashingService.hashPassword('timing-prevention');
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    if (!user.is_verified)
      return res.status(403).json({ error: 'Please verify your email before logging in.' });
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const mins = Math.ceil((new Date(user.locked_until) - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked. Try again in ${mins} minute(s)` });
    }
    if (!user.is_active)
      return res.status(403).json({ error: 'Account suspended. Contact administrator.' });

    const valid = await hashingService.verifyPassword(password, user.password_hash);
    if (!valid) {
      const attempts = user.login_attempts + 1;
      const lock = attempts >= MAX_LOGIN_ATTEMPTS ? new Date(Date.now() + LOCK_MS) : null;
      await q('UPDATE users SET login_attempts=?, locked_until=? WHERE id=?', [attempts, lock, user.id]);
      await q('INSERT INTO audit_log (id,action,user_id,ip_hash,meta) VALUES (?,?,?,?,?)',
        [uuid(), 'LOGIN_FAILED', user.id, secUtils.hashIP(req.ip), JSON.stringify({ attempts })]);
      if (lock) return res.status(401).json({ error: `Account locked for ${LOCK_MS / 60000} minutes due to too many failed attempts.` });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await q('UPDATE users SET login_attempts=0, locked_until=NULL, last_login=NOW() WHERE id=?', [user.id]);
    const token = keyMgmt.generateToken({ id: user.id, role: user.role, name: user.full_name });
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'LOGIN_SUCCESS', user.id, secUtils.hashIP(req.ip)]);

    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email, voter_id: user.voter_id, role: user.role } });
  } catch (e) {
    console.error('[LOGIN]', e);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

/* ── LOGOUT ── */
router.post('/logout', authMiddleware.authenticate, async (req, res) => {
  blacklistToken(req.token);
  await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
    [uuid(), 'LOGOUT', req.user.id, secUtils.hashIP(req.ip)]).catch(() => {});
  res.json({ message: 'Logged out successfully' });
});

/* ── ME ── */
router.get('/me', authMiddleware.authenticate, async (req, res) => {
  try {
    const user = await q1(
      'SELECT id, full_name, email, matric_number, dept_code, entry_year, faculty, voter_id, role, is_verified, created_at FROM users WHERE id=?',
      [req.user.id]
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (e) {
    console.error('[ME]', e);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

/* ── ADMIN LOGIN ── */
router.post('/admin-login', authLimiter, async (req, res) => {
  try {
    const { email, password, admin_key } = req.body;
    if (!email || !password || !admin_key)
      return res.status(400).json({ error: 'Email, password and admin key are required' });

    const expectedKey = process.env.ADMIN_SECRET_KEY || '';
    if (!expectedKey) return res.status(500).json({ error: 'Admin login not configured' });

    if (!secUtils.safeCompare(admin_key, expectedKey)) {
      await q('INSERT INTO audit_log (id,action,ip_hash,meta) VALUES (?,?,?,?)',
        [uuid(), 'ADMIN_LOGIN_INVALID_KEY', secUtils.hashIP(req.ip), JSON.stringify({ email })]);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = await q1('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.role !== 'admin') {
      await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
        [uuid(), 'ADMIN_LOGIN_DENIED', user.id, secUtils.hashIP(req.ip)]);
      return res.status(403).json({ error: 'Access denied. Administrator account required.' });
    }
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const mins = Math.ceil((new Date(user.locked_until) - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked. Try again in ${mins} minute(s)` });
    }
    if (!user.is_active) return res.status(403).json({ error: 'Account suspended' });

    const valid = await hashingService.verifyPassword(password, user.password_hash);
    if (!valid) {
      const attempts = user.login_attempts + 1;
      const lock = attempts >= MAX_LOGIN_ATTEMPTS ? new Date(Date.now() + LOCK_MS) : null;
      await q('UPDATE users SET login_attempts=?, locked_until=? WHERE id=?', [attempts, lock, user.id]);
      await q('INSERT INTO audit_log (id,action,user_id,ip_hash,meta) VALUES (?,?,?,?,?)',
        [uuid(), 'ADMIN_LOGIN_FAILED', user.id, secUtils.hashIP(req.ip), JSON.stringify({ attempts })]);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await q('UPDATE users SET login_attempts=0, locked_until=NULL, last_login=NOW() WHERE id=?', [user.id]);
    const token = keyMgmt.generateToken({ id: user.id, role: user.role, name: user.full_name });
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'ADMIN_LOGIN_SUCCESS', user.id, secUtils.hashIP(req.ip)]);

    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email, voter_id: user.voter_id, role: user.role } });
  } catch (e) {
    console.error('[ADMIN LOGIN]', e);
    res.status(500).json({ error: 'Admin login failed' });
  }
});

/* ── FORGOT PASSWORD ── */
router.post('/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await q1('SELECT id, full_name, is_verified FROM users WHERE email=?', [email.toLowerCase()]);

    // Always return same response to prevent email enumeration
    if (!user || !user.is_verified) {
      return res.json({ message: 'If that email is registered and verified, a reset link has been sent.' });
    }

    // Invalidate any existing unused tokens for this user
    await q('UPDATE password_reset_tokens SET used=1 WHERE user_id=? AND used=0', [user.id]);

    const token     = uuid();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await q('INSERT INTO password_reset_tokens (id,user_id,token,expires_at) VALUES (?,?,?,?)',
      [uuid(), user.id, token, expiresAt]);

    await sendPasswordResetEmail(email.toLowerCase(), user.full_name, token);
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'PASSWORD_RESET_REQUESTED', user.id, secUtils.hashIP(req.ip)]);

    res.json({ message: 'If that email is registered and verified, a reset link has been sent.' });
  } catch (e) {
    console.error('[FORGOT PASSWORD]', e);
    res.status(500).json({ error: 'Failed to process request. Please try again.' });
  }
});

/* ── VALIDATE RESET TOKEN (pre-check before showing reset form) ── */
router.get('/reset-password/validate', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ valid: false });
    const record = await q1(
      'SELECT expires_at FROM password_reset_tokens WHERE token=? AND used=0', [token]
    );
    if (!record || new Date(record.expires_at) < new Date())
      return res.json({ valid: false, error: 'Invalid or expired reset link' });
    res.json({ valid: true });
  } catch (e) {
    res.status(500).json({ valid: false });
  }
});

/* ── RESET PASSWORD ── */
router.post('/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and new password are required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const record = await q1(
      'SELECT * FROM password_reset_tokens WHERE token=? AND used=0', [token]
    );
    if (!record) return res.status(400).json({ error: 'Invalid or expired reset link' });
    if (new Date(record.expires_at) < new Date())
      return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });

    const password_hash = await hashingService.hashPassword(password);
    await q('UPDATE users SET password_hash=?, login_attempts=0, locked_until=NULL WHERE id=?',
      [password_hash, record.user_id]);
    await q('UPDATE password_reset_tokens SET used=1 WHERE id=?', [record.id]);
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'PASSWORD_RESET_SUCCESS', record.user_id, secUtils.hashIP(req.ip)]);

    res.json({ message: 'Password reset successfully. You can now log in with your new password.' });
  } catch (e) {
    console.error('[RESET PASSWORD]', e);
    res.status(500).json({ error: 'Password reset failed. Please try again.' });
  }
});

module.exports = router;
