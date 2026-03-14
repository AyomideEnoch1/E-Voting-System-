const express        = require('express');
const router         = express.Router();
const { v4: uuid }   = require('uuid');
const authMiddleware = require('./auth_middleware');
const secUtils       = require('./security_utils');
const { q, q1, qa }  = require('./database');
const {
  sendVoterIdEmail,
  sendVoterIdResetApproved,
  sendVoterIdResetRejected
} = require('./email_service');

const auth    = authMiddleware.authenticate.bind(authMiddleware);
const isAdmin = authMiddleware.authorize('admin');

/* ── LIST USERS ── */
router.get('/users', auth, isAdmin, async (req, res) => {
  try {
    const { role, search, page = 1, limit = 20 } = req.query;
    let sql      = `SELECT id,full_name,email,voter_id,role,is_active,is_verified,login_attempts,last_login,created_at FROM users WHERE 1=1`;
    let countSql = `SELECT COUNT(*) AS total FROM users WHERE 1=1`;
    const params = [], countParams = [];
    if (role)   { sql += ' AND role=?';   countSql += ' AND role=?';   params.push(role);   countParams.push(role); }
    if (search) { sql += ' AND (full_name LIKE ? OR email LIKE ?)'; countSql += ' AND (full_name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`,`%${search}%`); countParams.push(`%${search}%`,`%${search}%`); }
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(+limit, (+page - 1) * +limit);
    const users      = await qa(sql, params);
    const countRows  = await q(countSql, countParams);
    const total      = countRows?.[0]?.[0]?.total ?? countRows?.[0]?.total ?? 0;
    res.json({ users, total, page: +page, limit: +limit });
  } catch (e) { console.error('[LIST USERS]', e); res.status(500).json({ error: 'Failed to fetch users' }); }
});

/* ── UPDATE USER ── */
router.put('/users/:id', auth, isAdmin, async (req, res) => {
  try {
    const target = await q1('SELECT * FROM users WHERE id=?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'User not found' });

    const { is_active, is_verified, role } = req.body;
    const newIsActive   = is_active   !== undefined ? (is_active   ? 1 : 0) : target.is_active;
    const newIsVerified = is_verified !== undefined ? (is_verified ? 1 : 0) : target.is_verified;
    const newRole       = role        !== undefined ? role                   : target.role;

    const validRoles = ['voter','admin','observer'];
    if (!validRoles.includes(newRole))
      return res.status(400).json({ error: `Invalid role. Must be: ${validRoles.join(', ')}` });

    await q('UPDATE users SET is_active=?,is_verified=?,role=? WHERE id=?',
      [newIsActive, newIsVerified, newRole, req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ADMIN_USER_UPDATE', req.user.id,
       JSON.stringify({ targetId: req.params.id, changes: { is_active: newIsActive, is_verified: newIsVerified, role: newRole } }),
       secUtils.hashIP(req.ip)]);
    res.json(await q1('SELECT id,full_name,email,role,is_active,is_verified FROM users WHERE id=?', [req.params.id]));
  } catch (e) { console.error('[UPDATE USER]', e); res.status(500).json({ error: 'Failed to update user' }); }
});

/* ── UNLOCK USER ── */
router.post('/users/:id/unlock', auth, isAdmin, async (req, res) => {
  try {
    const target = await q1('SELECT id FROM users WHERE id=?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'User not found' });
    await q('UPDATE users SET login_attempts=0,locked_until=NULL WHERE id=?', [req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ADMIN_USER_UNLOCKED', req.user.id, JSON.stringify({ targetId: req.params.id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'User account unlocked' });
  } catch (e) { console.error('[UNLOCK USER]', e); res.status(500).json({ error: 'Failed to unlock user' }); }
});

/* ── MANUALLY VERIFY VOTER & ASSIGN VOTER ID ── */
router.post('/users/:id/verify', auth, isAdmin, async (req, res) => {
  try {
    const user = await q1('SELECT * FROM users WHERE id=?', [req.params.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.is_verified) return res.status(400).json({ error: 'User is already verified' });

    let voterId, exists;
    do {
      voterId = `VTR-${Math.floor(100000 + Math.random() * 900000)}`;
      exists  = await q1('SELECT id FROM users WHERE voter_id=?', [voterId]);
    } while (exists);

    await q(
      `UPDATE users SET is_verified=1,voter_id=?,verification_token=NULL,
        verification_token_expiry=NULL WHERE id=?`,
      [voterId, user.id]
    );

    // Non-fatal: voter ID is already saved — email failure must not return 500
    try {
      await sendVoterIdEmail(user.email, user.full_name, voterId);
    } catch (emailErr) {
      console.error('[MANUAL VERIFY] Email failed (non-fatal):', emailErr.message);
    }
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ADMIN_MANUAL_VERIFY', req.user.id,
       JSON.stringify({ targetId: user.id, voter_id: voterId }),
       secUtils.hashIP(req.ip)]);

    res.json({ message: 'Voter verified successfully', voter_id: voterId });
  } catch (e) {
    console.error('[MANUAL VERIFY]', e);
    res.status(500).json({ error: 'Verification failed' });
  }
});

/* ── AUDIT LOG ── */
router.get('/audit-log', auth, isAdmin, async (req, res) => {
  try {
    const { action, page = 1, limit = 50 } = req.query;
    let sql      = `SELECT a.*,u.full_name AS user_name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id WHERE 1=1`;
    let countSql = `SELECT COUNT(*) AS total FROM audit_log WHERE 1=1`;
    const params = [], countParams = [];
    if (action) { sql += ' AND a.action=?'; countSql += ' AND action=?'; params.push(action); countParams.push(action); }
    sql += ' ORDER BY a.created_at DESC LIMIT ? OFFSET ?';
    params.push(+limit, (+page - 1) * +limit);
    const logs      = await qa(sql, params);
    const countRows = await q(countSql, countParams);
    const total     = countRows?.[0]?.[0]?.total ?? countRows?.[0]?.total ?? 0;
    res.json({ logs, total, page: +page, limit: +limit });
  } catch (e) { console.error('[AUDIT LOG]', e); res.status(500).json({ error: 'Failed to fetch audit log' }); }
});

/* ── STATS ── */
router.get('/stats', auth, isAdmin, async (req, res) => {
  try {
    const getCount = async (sql) => {
      const rows = await q(sql);
      return rows?.[0]?.[0]?.total ?? rows?.[0]?.total ?? 0;
    };
    const totalUsers      = await getCount('SELECT COUNT(*) AS total FROM users');
    const totalElections  = await getCount('SELECT COUNT(*) AS total FROM elections');
    const totalVotes      = await getCount('SELECT COUNT(*) AS total FROM vote_registry');
    const activeElections = await getCount("SELECT COUNT(*) AS total FROM elections WHERE status='active'");
    const recentLogs = await qa(
      `SELECT a.action,a.created_at,u.full_name AS user_name FROM audit_log a
       LEFT JOIN users u ON a.user_id=u.id ORDER BY a.created_at DESC LIMIT 10`
    );
    res.json({ totalUsers, totalElections, totalVotes, activeElections, recentLogs });
  } catch (e) { console.error('[STATS]', e); res.status(500).json({ error: 'Failed to fetch stats' }); }
});

/* ── CREATE ADMIN ── */
router.post('/create-admin', auth, isAdmin, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const user = await q1('SELECT id,role FROM users WHERE email=?', [email.toLowerCase()]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.role === 'admin') return res.status(400).json({ error: 'User is already an admin' });
    await q("UPDATE users SET role='admin' WHERE id=?", [user.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ADMIN_PROMOTED', req.user.id, JSON.stringify({ targetId: user.id, targetEmail: email }), secUtils.hashIP(req.ip)]);
    res.json({ message: `User ${email} promoted to admin` });
  } catch (e) { console.error('[CREATE ADMIN]', e); res.status(500).json({ error: 'Failed to promote user' }); }
});

/* ── LIST VOTER ID RESET REQUESTS ── */
router.get('/voter-id-requests', auth, isAdmin, async (req, res) => {
  try {
    const { status = 'pending' } = req.query;
    const requests = await qa(
      `SELECT r.id, r.reason, r.status, r.admin_note, r.created_at, r.reviewed_at,
              u.id AS user_id, u.full_name, u.email, u.voter_id,
              a.full_name AS reviewed_by_name
       FROM voter_id_reset_requests r
       JOIN users u ON r.user_id = u.id
       LEFT JOIN users a ON r.reviewed_by = a.id
       WHERE r.status = ?
       ORDER BY r.created_at DESC`,
      [status]
    );
    res.json({ requests });
  } catch (e) {
    console.error('[VOTER ID REQUESTS]', e);
    res.status(500).json({ error: 'Failed to load requests' });
  }
});

/* ── APPROVE VOTER ID RESET REQUEST ── */
router.post('/voter-id-requests/:id/approve', auth, isAdmin, async (req, res) => {
  try {
    const request = await q1(
      `SELECT r.*, u.email, u.full_name FROM voter_id_reset_requests r
       JOIN users u ON r.user_id = u.id WHERE r.id = ?`,
      [req.params.id]
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ error: 'Request has already been reviewed' });

    let newVoterId, exists;
    do {
      newVoterId = `VTR-${Math.floor(100000 + Math.random() * 900000)}`;
      exists = await q1('SELECT id FROM users WHERE voter_id=?', [newVoterId]);
    } while (exists);

    const reviewedAt = new Date().toISOString();
    await q('UPDATE users SET voter_id=? WHERE id=?', [newVoterId, request.user_id]);
    await q(
      `UPDATE voter_id_reset_requests
       SET status='approved', reviewed_by=?, reviewed_at=?, admin_note=?
       WHERE id=?`,
      [req.user.id, reviewedAt, req.body.admin_note || null, req.params.id]
    );

    // Non-fatal: new voter ID is already saved — email failure must not return 500
    try {
      await sendVoterIdResetApproved(request.email, request.full_name, newVoterId);
    } catch (emailErr) {
      console.error('[APPROVE VOTER ID] Email failed (non-fatal):', emailErr.message);
    }
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'VOTER_ID_RESET_APPROVED', req.user.id,
       JSON.stringify({ requestId: req.params.id, targetUser: request.user_id, newVoterId }),
       secUtils.hashIP(req.ip)]);

    res.json({ message: 'Request approved. New Voter ID issued and emailed.', new_voter_id: newVoterId });
  } catch (e) {
    console.error('[APPROVE VOTER ID REQUEST]', e);
    res.status(500).json({ error: 'Failed to approve request' });
  }
});

/* ── REJECT VOTER ID RESET REQUEST ── */
router.post('/voter-id-requests/:id/reject', auth, isAdmin, async (req, res) => {
  try {
    const request = await q1(
      `SELECT r.*, u.email, u.full_name FROM voter_id_reset_requests r
       JOIN users u ON r.user_id = u.id WHERE r.id = ?`,
      [req.params.id]
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ error: 'Request has already been reviewed' });

    const reviewedAt = new Date().toISOString();
    await q(
      `UPDATE voter_id_reset_requests
       SET status='rejected', reviewed_by=?, reviewed_at=?, admin_note=?
       WHERE id=?`,
      [req.user.id, reviewedAt, req.body.admin_note || null, req.params.id]
    );

    // Non-fatal: rejection is already recorded — email failure must not return 500
    try {
      await sendVoterIdResetRejected(request.email, request.full_name, req.body.admin_note || null);
    } catch (emailErr) {
      console.error('[REJECT VOTER ID] Email failed (non-fatal):', emailErr.message);
    }
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'VOTER_ID_RESET_REJECTED', req.user.id,
       JSON.stringify({ requestId: req.params.id, targetUser: request.user_id }),
       secUtils.hashIP(req.ip)]);

    res.json({ message: 'Request rejected.' });
  } catch (e) {
    console.error('[REJECT VOTER ID REQUEST]', e);
    res.status(500).json({ error: 'Failed to reject request' });
  }
});

module.exports = router;
