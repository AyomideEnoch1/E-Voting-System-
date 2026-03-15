const express        = require('express');
const router         = express.Router();
const { v4: uuid }   = require('uuid');
const authMiddleware = require('./auth_middleware');
const secUtils       = require('./security_utils');
const { q, q1, qa }  = require('./database');
const { sendElectionNotice, sendVoterIdResetApproved, sendVoterIdResetRejected } = require('./email_service');

const auth    = authMiddleware.authenticate.bind(authMiddleware);
const isAdmin = authMiddleware.authorize('admin');

/* ── LIST USERS ── */
router.get('/users', auth, isAdmin, async (req, res) => {
  try {
    // FIXED: added is_verified and is_active server-side filter params
    // Previously the frontend filtered client-side on only the first page of 20 results,
    // meaning users on page 2+ were invisible when a filter was active.
    const { role, search, is_verified, is_active, page = 1, limit = 20 } = req.query;
    let sql      = `SELECT id,full_name,email,voter_id,role,is_active,is_verified,login_attempts,last_login,created_at FROM users WHERE 1=1`;
    let countSql = `SELECT COUNT(*) AS total FROM users WHERE 1=1`;
    const params = [], countParams = [];
    if (role)   { sql += ' AND role=?';   countSql += ' AND role=?';   params.push(role);   countParams.push(role); }
    if (search) { sql += ' AND (full_name LIKE ? OR email LIKE ?)'; countSql += ' AND (full_name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`,`%${search}%`); countParams.push(`%${search}%`,`%${search}%`); }
    // FIXED: server-side verified/active filters
    if (is_verified !== undefined && is_verified !== '') {
      sql += ' AND is_verified=?'; countSql += ' AND is_verified=?';
      params.push(+is_verified); countParams.push(+is_verified);
    }
    if (is_active !== undefined && is_active !== '') {
      sql += ' AND is_active=?'; countSql += ' AND is_active=?';
      params.push(+is_active); countParams.push(+is_active);
    }
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(+limit, (+page - 1) * +limit);
    const users = await qa(sql, params);
    const [[{ total }]] = await q(countSql, countParams);
    res.json({ users, total, page: +page, limit: +limit });
  } catch (e) { console.error('[LIST USERS]', e); res.status(500).json({ error: 'Failed to fetch users' }); }
});

/* ── UPDATE USER ── */
router.put('/users/:id', auth, isAdmin, async (req, res) => {
  try {
    const target = await q1('SELECT * FROM users WHERE id=?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'User not found' });

    const { is_active, is_verified, role } = req.body;
    // FIX: only update provided fields — prevents accidental NULL writes
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

/* ── MANUAL VERIFY USER ── */
router.post('/users/:id/verify', auth, isAdmin, async (req, res) => {
  try {
    const target = await q1('SELECT id, is_verified, voter_id FROM users WHERE id=?', [req.params.id]);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.is_verified) return res.status(400).json({ error: 'User is already verified' });

    // Generate a unique Voter ID if not yet assigned
    let voter_id = target.voter_id;
    if (!voter_id) {
      let exists, attempts = 0;
      do {
        if (++attempts > 20) throw new Error('Could not generate unique Voter ID');
        voter_id = `VTR-${Math.floor(100000 + Math.random() * 900000)}`;
        exists = await q1('SELECT id FROM users WHERE voter_id=?', [voter_id]);
      } while (exists);
    }

    await q('UPDATE users SET is_verified=1, voter_id=? WHERE id=?', [voter_id, req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ADMIN_USER_VERIFIED', req.user.id, JSON.stringify({ targetId: req.params.id, voter_id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'User verified', voter_id });
  } catch (e) { console.error('[MANUAL VERIFY]', e); res.status(500).json({ error: 'Verification failed' }); }
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
    const logs = await qa(sql, params);
    // FIX: count also respects action filter
    const [[{ total }]] = await q(countSql, countParams);
    res.json({ logs, total, page: +page, limit: +limit });
  } catch (e) { console.error('[AUDIT LOG]', e); res.status(500).json({ error: 'Failed to fetch audit log' }); }
});

/* ── STATS ── */
router.get('/stats', auth, isAdmin, async (req, res) => {
  try {
    const [[{ totalUsers }]]      = await q('SELECT COUNT(*) AS totalUsers FROM users');
    const [[{ totalElections }]]  = await q('SELECT COUNT(*) AS totalElections FROM elections');
    const [[{ totalVotes }]]      = await q('SELECT COUNT(*) AS totalVotes FROM vote_registry');
    const [[{ activeElections }]] = await q("SELECT COUNT(*) AS activeElections FROM elections WHERE status='active'");
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

/* ── NOTIFY ALL VERIFIED VOTERS ── */
router.post('/notify-voters', auth, isAdmin, async (req, res) => {
  try {
    const { election_id, custom_message: rawMessage } = req.body;
    if (!election_id) return res.status(400).json({ error: 'election_id is required' });
    // Sanitise custom message — strip HTML tags and cap length to prevent abuse
    const custom_message = rawMessage ? String(rawMessage).replace(/<[^>]*>/g, '').trim().substring(0, 1000) : '';

    const election = await q1('SELECT id,title,start_time,end_time FROM elections WHERE id=?', [election_id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });

    // Fetch all active, verified voters
    const voters = await qa(
      `SELECT email, full_name FROM users WHERE is_active=1 AND is_verified=1 AND role='voter'`
    );
    if (!voters.length) return res.status(404).json({ error: 'No verified voters found' });

    let sent = 0, failed = 0;
    for (const voter of voters) {
      try {
        await sendElectionNotice(voter.email, voter.full_name, {
          electionTitle: election.title,
          startTime:     election.start_time,
          endTime:       election.end_time,
          customMessage: custom_message || ''
        });
        sent++;
      } catch {
        failed++;
      }
    }

    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'VOTERS_NOTIFIED', req.user.id,
       JSON.stringify({ electionId: election_id, sent, failed }), secUtils.hashIP(req.ip)]);

    res.json({
      message: `Notification sent to ${sent} voter(s)${failed ? `, ${failed} failed` : ''}`,
      sent,
      failed
    });
  } catch (e) {
    console.error('[NOTIFY VOTERS]', e);
    res.status(500).json({ error: 'Failed to send notifications' });
  }
});

/* ── LIST VOTER ID RESET REQUESTS ── */
router.get('/voter-id-requests', auth, isAdmin, async (req, res) => {
  try {
    const { status = 'pending', page = 1, limit = 50 } = req.query;
    const requests = await qa(
      `SELECT r.id, r.reason, r.status, r.reject_reason, r.created_at, r.reviewed_at,
              u.full_name, u.email, u.voter_id,
              a.full_name AS reviewed_by_name
       FROM voter_id_reset_requests r
       JOIN users u ON r.user_id = u.id
       LEFT JOIN users a ON r.reviewed_by = a.id
       WHERE r.status = ?
       ORDER BY r.created_at DESC
       LIMIT ? OFFSET ?`,
      [status, +limit, (+page - 1) * +limit]
    );
    res.json(requests);
  } catch (e) {
    console.error('[VOTER ID REQUESTS]', e);
    res.status(500).json({ error: 'Failed to fetch requests' });
  }
});

/* ── APPROVE VOTER ID RESET ── */
router.post('/voter-id-requests/:id/approve', auth, isAdmin, async (req, res) => {
  try {
    const request = await q1(
      `SELECT r.*, u.email, u.full_name
       FROM voter_id_reset_requests r
       JOIN users u ON r.user_id = u.id
       WHERE r.id = ?`,
      [req.params.id]
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ error: 'Request already reviewed' });

    // Generate new unique Voter ID (cap at 20 attempts to prevent infinite loop)
    let newVoterId, exists, attempts = 0;
    do {
      if (++attempts > 20) throw new Error('Could not generate a unique Voter ID — please try again.');
      newVoterId = `VTR-${Math.floor(100000 + Math.random() * 900000)}`;
      exists = await q1('SELECT id FROM users WHERE voter_id=?', [newVoterId]);
    } while (exists);

    await q('UPDATE users SET voter_id=? WHERE id=?', [newVoterId, request.user_id]);
    await q(
      `UPDATE voter_id_reset_requests
       SET status='approved', reviewed_by=?, reviewed_at=NOW()
       WHERE id=?`,
      [req.user.id, req.params.id]
    );
    await sendVoterIdResetApproved(request.email, request.full_name, newVoterId);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'VOTER_ID_RESET_APPROVED', req.user.id,
       JSON.stringify({ targetUserId: request.user_id, newVoterId }),
       secUtils.hashIP(req.ip)]);

    res.json({ message: `Voter ID reset approved. New ID ${newVoterId} sent to ${request.email}.` });
  } catch (e) {
    console.error('[APPROVE VOTER ID]', e);
    res.status(500).json({ error: 'Failed to approve request' });
  }
});

/* ── REJECT VOTER ID RESET ── */
router.post('/voter-id-requests/:id/reject', auth, isAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    const request = await q1(
      `SELECT r.*, u.email, u.full_name
       FROM voter_id_reset_requests r
       JOIN users u ON r.user_id = u.id
       WHERE r.id = ?`,
      [req.params.id]
    );
    if (!request) return res.status(404).json({ error: 'Request not found' });
    if (request.status !== 'pending') return res.status(400).json({ error: 'Request already reviewed' });

    await q(
      `UPDATE voter_id_reset_requests
       SET status='rejected', reviewed_by=?, reviewed_at=NOW(), reject_reason=?
       WHERE id=?`,
      [req.user.id, reason || null, req.params.id]
    );
    await sendVoterIdResetRejected(request.email, request.full_name, reason);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'VOTER_ID_RESET_REJECTED', req.user.id,
       JSON.stringify({ targetUserId: request.user_id, reason }),
       secUtils.hashIP(req.ip)]);

    res.json({ message: 'Request rejected and voter notified.' });
  } catch (e) {
    console.error('[REJECT VOTER ID]', e);
    res.status(500).json({ error: 'Failed to reject request' });
  }
});

module.exports = router;
