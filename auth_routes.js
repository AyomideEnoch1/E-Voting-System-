const express            = require('express');
const router             = express.Router();
const { v4: uuid }       = require('uuid');
const hashingService     = require('./hashing_service');
const keyMgmt            = require('./key-management_service');
const authMiddleware     = require('./auth_middleware');
const { blacklistToken } = require('./auth_middleware');
const { authLimiter }    = require('./rate-limit_middleware');
const secUtils           = require('./security_utils');
const { q, q1 }          = require('./database');
const { sendVerificationEmail, sendVoterIdEmail, sendPasswordResetEmail } = require('./email_service');

const SCHOOL_EMAIL_DOMAIN = '@run.edu.ng';
const MAX_LOGIN_ATTEMPTS  = 5;
const LOCK_DURATION_MS    = 15 * 60 * 1000;

async function generateVoterId() {
  let voterId, exists;
  do {
    voterId = `VTR-${Math.floor(100000 + Math.random() * 900000)}`;
    exists  = await q1('SELECT id FROM users WHERE voter_id=?', [voterId]);
  } while (exists);
  return voterId;
}

/* ── REGISTER ── */
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { full_name, email, password } = req.body;
    if (!full_name || !email || !password)
      return res.status(400).json({ error: 'full_name, email and password are required' });
    if (full_name.trim().length < 2)
      return res.status(400).json({ error: 'Please provide your full name' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!email.toLowerCase().endsWith(SCHOOL_EMAIL_DOMAIN))
      return res.status(400).json({ error: `Only ${SCHOOL_EMAIL_DOMAIN} email addresses are allowed` });
    if (await q1('SELECT id FROM users WHERE email=?', [email.toLowerCase()]))
      return res.status(400).json({ error: 'Email already registered' });

    const id                = uuid();
    const password_hash     = await hashingService.hashPassword(password);
    const { publicKey }     = keyMgmt.generateECDSAKeyPair();
    const verificationToken = uuid();
    const tokenExpiry       = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await q(
      `INSERT INTO users (id,full_name,email,voter_id,password_hash,role,public_key,
        is_verified,verification_token,verification_token_expiry)
       VALUES (?,?,?,NULL,?,?,?,0,?,?)`,
      [id, secUtils.sanitize(full_name.trim()), email.toLowerCase(),
       password_hash, 'voter', publicKey, verificationToken, tokenExpiry]
    );
    try { await sendVerificationEmail(email.toLowerCase(), verificationToken, full_name.trim()); }
    catch (e) { console.error('[REGISTER] email failed (non-fatal):', e.message); }
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'USER_REGISTERED', id, secUtils.hashIP(req.ip)]);
    res.status(201).json({ message: `Registration successful! A verification link has been sent to ${email}.` });
  } catch (e) { console.error('[REGISTER]', e); res.status(500).json({ error: 'Registration failed.' }); }
});

/* ── VERIFY EMAIL ── */
router.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Verification token is required' });
    const user = await q1('SELECT * FROM users WHERE verification_token=?', [token]);
    if (!user) return res.status(400).json({ error: 'Invalid or already used verification link' });
    if (user.is_verified) {
      await q('UPDATE users SET verification_token=NULL,verification_token_expiry=NULL WHERE id=?', [user.id]);
      return res.redirect(`/login?verified=1&email=${encodeURIComponent(user.email)}`);
    }
    if (new Date(user.verification_token_expiry) < new Date()) {
      await q('UPDATE users SET verification_token=NULL,verification_token_expiry=NULL WHERE id=?', [user.id]);
      return res.status(400).json({ error: 'Verification link expired. Please register again.' });
    }
    const voterId = await generateVoterId();
    await q(
      `UPDATE users SET is_verified=1,voter_id=?,verification_token=NULL,
        verification_token_expiry=NULL WHERE id=? AND is_verified=0`,
      [voterId, user.id]
    );
    try { await sendVoterIdEmail(user.email, user.full_name, voterId); }
    catch (e) { console.error('[VERIFY EMAIL] voter ID email failed (non-fatal):', e.message); }
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'EMAIL_VERIFIED', user.id, secUtils.hashIP(req.ip)]);
    res.redirect(`/login?verified=1&email=${encodeURIComponent(user.email)}`);
  } catch (e) { console.error('[VERIFY EMAIL]', e); res.status(500).json({ error: 'Email verification failed.' }); }
});

/* ── LOGIN ── */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await q1('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
    if (!user) { await hashingService.hashPassword('timing-prevention'); return res.status(401).json({ error: 'Invalid email or password' }); }
    if (!user.is_verified) return res.status(403).json({ error: 'Please verify your email before logging in.' });
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const mins = Math.ceil((new Date(user.locked_until) - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked. Try again in ${mins} minute(s)` });
    }
    if (!user.is_active) return res.status(403).json({ error: 'Account suspended. Contact administrator.' });
    const valid = await hashingService.verifyPassword(password, user.password_hash);
    if (!valid) {
      const attempts = user.login_attempts + 1;
      const lock = attempts >= MAX_LOGIN_ATTEMPTS ? new Date(Date.now() + LOCK_DURATION_MS) : null;
      await q('UPDATE users SET login_attempts=?,locked_until=? WHERE id=?', [attempts, lock, user.id]);
      await q('INSERT INTO audit_log (id,action,user_id,ip_hash,meta) VALUES (?,?,?,?,?)',
        [uuid(), 'LOGIN_FAILED', user.id, secUtils.hashIP(req.ip), JSON.stringify({ attempts })]);
      if (lock) return res.status(401).json({ error: `Account locked for ${LOCK_DURATION_MS/60000} minutes.` });
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    await q('UPDATE users SET login_attempts=0,locked_until=NULL,last_login=NOW() WHERE id=?', [user.id]);
    const token = keyMgmt.generateToken({ id: user.id, role: user.role, name: user.full_name });
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'LOGIN_SUCCESS', user.id, secUtils.hashIP(req.ip)]);
    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email, voter_id: user.voter_id, role: user.role } });
  } catch (e) { console.error('[LOGIN]', e); res.status(500).json({ error: 'Login failed.' }); }
});

/* ── LOGOUT ── */
router.post('/logout', authMiddleware.authenticate, async (req, res) => {
  try {
    blacklistToken(req.token);
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'LOGOUT', req.user.id, secUtils.hashIP(req.ip)]);
    res.json({ message: 'Logged out successfully' });
  } catch (e) { console.error('[LOGOUT]', e); res.json({ message: 'Logged out successfully' }); }
});

/* ── ME ── */
router.get('/me', authMiddleware.authenticate, async (req, res) => {
  try {
    const user = await q1(
      'SELECT id,full_name,email,voter_id,role,is_verified,created_at FROM users WHERE id=?',
      [req.user.id]
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (e) { console.error('[ME]', e); res.status(500).json({ error: 'Failed to fetch user' }); }
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
      const lock = attempts >= MAX_LOGIN_ATTEMPTS ? new Date(Date.now() + LOCK_DURATION_MS) : null;
      await q('UPDATE users SET login_attempts=?,locked_until=? WHERE id=?', [attempts, lock, user.id]);
      await q('INSERT INTO audit_log (id,action,user_id,ip_hash,meta) VALUES (?,?,?,?,?)',
        [uuid(), 'ADMIN_LOGIN_FAILED', user.id, secUtils.hashIP(req.ip), JSON.stringify({ attempts })]);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    await q('UPDATE users SET login_attempts=0,locked_until=NULL,last_login=NOW() WHERE id=?', [user.id]);
    const token = keyMgmt.generateToken({ id: user.id, role: user.role, name: user.full_name });
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'ADMIN_LOGIN_SUCCESS', user.id, secUtils.hashIP(req.ip)]);
    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email, voter_id: user.voter_id, role: user.role } });
  } catch (e) { console.error('[ADMIN LOGIN]', e); res.status(500).json({ error: 'Admin login failed' }); }
});

/* ── CHANGE PASSWORD ── */
router.put('/change-password', authMiddleware.authenticate, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password)
      return res.status(400).json({ error: 'current_password and new_password are required' });
    if (new_password.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
    if (current_password === new_password) return res.status(400).json({ error: 'New password must differ from current' });
    const user = await q1('SELECT id,password_hash FROM users WHERE id=?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const valid = await hashingService.verifyPassword(current_password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    const new_hash = await hashingService.hashPassword(new_password);
    await q('UPDATE users SET password_hash=? WHERE id=?', [new_hash, user.id]);
    blacklistToken(req.token);
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'PASSWORD_CHANGED', user.id, secUtils.hashIP(req.ip)]);
    res.json({ message: 'Password updated successfully.' });
  } catch (e) { console.error('[CHANGE PASSWORD]', e); res.status(500).json({ error: 'Failed to update password.' }); }
});

/* ── FORGOT PASSWORD ── */
router.post('/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const user = await q1('SELECT id,full_name,email,is_verified FROM users WHERE email=?', [email.toLowerCase()]);
    // Always return success to prevent user enumeration
    if (!user || !user.is_verified)
      return res.json({ message: 'If that email is registered, a reset link has been sent.' });
    const resetToken  = uuid();
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000);
    await q('UPDATE users SET verification_token=?,verification_token_expiry=? WHERE id=?',
      [resetToken, resetExpiry, user.id]);
    try { await sendPasswordResetEmail(user.email, user.full_name, resetToken); }
    catch (e) { console.error('[FORGOT PASSWORD] email failed (non-fatal):', e.message); }
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'PASSWORD_RESET_REQUESTED', user.id, secUtils.hashIP(req.ip)]);
    res.json({ message: 'If that email is registered, a reset link has been sent.' });
  } catch (e) { console.error('[FORGOT PASSWORD]', e); res.status(500).json({ error: 'Failed to process request.' }); }
});

/* ── VALIDATE RESET TOKEN ── */
router.get('/reset-password/validate', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.json({ valid: false });
    const user = await q1('SELECT id,verification_token_expiry FROM users WHERE verification_token=?', [token]);
    if (!user || new Date(user.verification_token_expiry) < new Date()) return res.json({ valid: false });
    res.json({ valid: true });
  } catch (e) { console.error('[VALIDATE RESET TOKEN]', e); res.json({ valid: false }); }
});

/* ── RESET PASSWORD ── */
router.post('/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, new_password } = req.body;
    if (!token || !new_password) return res.status(400).json({ error: 'token and new_password are required' });
    if (new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    const user = await q1('SELECT * FROM users WHERE verification_token=?', [token]);
    if (!user) return res.status(400).json({ error: 'Invalid or already used reset link' });
    if (new Date(user.verification_token_expiry) < new Date())
      return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
    const new_hash = await hashingService.hashPassword(new_password);
    await q('UPDATE users SET password_hash=?,verification_token=NULL,verification_token_expiry=NULL WHERE id=?',
      [new_hash, user.id]);
    await q('INSERT INTO audit_log (id,action,user_id,ip_hash) VALUES (?,?,?,?)',
      [uuid(), 'PASSWORD_RESET_COMPLETED', user.id, secUtils.hashIP(req.ip)]);
    res.json({ message: 'Password reset successfully. You can now log in.' });
  } catch (e) { console.error('[RESET PASSWORD]', e); res.status(500).json({ error: 'Failed to reset password.' }); }
});

module.exports = router;
