const express        = require('express');
const router         = express.Router();
const { v4: uuid }   = require('uuid');
const authMiddleware = require('./auth_middleware');
const { voteLimiter }   = require('./rate-limit_middleware');
const encService        = require('./encryption_service');
const sigService        = require('./digital-signature_service');
const hashService       = require('./hashing_service');
const secUtils          = require('./security_utils');
const { parseMatric, checkEligibility } = require('./matric_utils');
const { q, q1 }         = require('./database');
const { sendVoterIdRequestReceived } = require('./email_service');

const auth    = authMiddleware.authenticate.bind(authMiddleware);
const isVoter = authMiddleware.authorize('voter', 'admin');

/* ── CAST VOTE ── */
router.post('/cast', auth, isVoter, voteLimiter, async (req, res) => {
  try {
    const { election_id, candidate_id, voter_id } = req.body;
    if (!election_id || !candidate_id)
      return res.status(400).json({ error: 'election_id and candidate_id are required' });

    // Validate voter_id if submitted
    if (voter_id) {
      const me = await q1('SELECT voter_id FROM users WHERE id=?', [req.user.id]);
      if (!me || me.voter_id !== voter_id.toUpperCase()) {
        return res.status(403).json({ error: 'Voter ID does not match your account. Please check and try again.' });
      }
    }

    const election = await q1('SELECT * FROM elections WHERE id=?', [election_id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (election.status !== 'active')
      return res.status(400).json({ error: 'Election is not currently open for voting' });

    const now = new Date();
    if (now < new Date(election.start_time) || now > new Date(election.end_time))
      return res.status(400).json({ error: 'Voting period is not active' });

    // ── ELIGIBILITY CHECK ──
    // Fetch the election's eligibility rules and the voter's matric profile.
    // If rules exist, every configured filter must pass before the vote is allowed.
    const rules = await q1(
      'SELECT * FROM election_eligibility_rules WHERE election_id=?', [election_id]
    );
    if (rules) {
      const voter = await q1(
        'SELECT faculty, matric_number, dept_code, entry_year, serial_number FROM users WHERE id=?',
        [req.user.id]
      );
      if (!voter || !voter.matric_number) {
        return res.status(403).json({ error: 'Your account does not have a matriculation number on record. Please contact the administrator.' });
      }
      const parsed = parseMatric(voter.matric_number);
      if (!parsed) {
        return res.status(403).json({ error: 'Your matriculation number could not be parsed. Please contact the administrator.' });
      }
      const { eligible, reason } = checkEligibility(parsed, rules, voter.faculty);
      if (!eligible) return res.status(403).json({ error: reason });
    }

    const candidate = await q1(
      'SELECT id FROM candidates WHERE id=? AND election_id=?', [candidate_id, election_id]
    );
    if (!candidate) return res.status(400).json({ error: 'Invalid candidate for this election' });

    // Fast-path duplicate check
    const already = await q1(
      'SELECT id FROM vote_registry WHERE voter_id=? AND election_id=?', [req.user.id, election_id]
    );
    if (already) return res.status(400).json({ error: 'You have already voted in this election' });

    // Decrypt election master key
    const keyData   = JSON.parse(election.master_key_enc);
    const masterKey = encService.decryptWithPassword(
      keyData.masterKey.encrypted, process.env.KEY_PASSPHRASE || 'default',
      keyData.masterKey.salt, keyData.masterKey.iv, keyData.masterKey.tag
    );

    const encryptedVote  = encService.encryptVote(candidate_id, masterKey);
    const electionSecret = hashService.hashData(election_id + masterKey);
    const anonymousId    = secUtils.anonymizeVoterId(req.user.id, election_id, electionSecret);
    const voteHash       = hashService.hashVoteRecord(anonymousId, candidate_id, election_id, encryptedVote.iv);

    // Decrypt election private key to sign receipt
    const privKeyData = keyData.privateKey;
    const privateKey  = encService.decryptWithPassword(
      privKeyData.encrypted, process.env.KEY_PASSPHRASE || 'default',
      privKeyData.salt, privKeyData.iv, privKeyData.tag
    );
    const receipt = sigService.generateVoteReceipt(anonymousId, election_id, privateKey);

    const voteId = uuid();
    await q(
      `INSERT INTO votes
         (id, election_id, anonymous_id, encrypted_vote, vote_iv, vote_tag,
          vote_hash, receipt_hash, receipt_sig, receipt_data)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [voteId, election_id, anonymousId, encryptedVote.encrypted, encryptedVote.iv,
       encryptedVote.tag, voteHash, receipt.receiptHash, receipt.signature, receipt.receiptData]
    );

    // Race-condition-safe registry insert
    try {
      await q('INSERT INTO vote_registry (id,voter_id,election_id,ip_hash) VALUES (?,?,?,?)',
        [uuid(), req.user.id, election_id, secUtils.hashIP(req.ip)]);
    } catch (dupErr) {
      if (dupErr.code === 'ER_DUP_ENTRY') {
        await q('DELETE FROM votes WHERE id=?', [voteId]).catch(() => {});
        return res.status(400).json({ error: 'You have already voted in this election' });
      }
      throw dupErr;
    }

    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'VOTE_CAST', req.user.id,
       JSON.stringify({ electionId: election_id, voteHash }), secUtils.hashIP(req.ip)]);

    res.json({
      message:      'Vote cast successfully',
      receipt_hash: receipt.receiptHash,
      receipt_data: receipt.receiptData,
      receipt_sig:  receipt.signature,
      vote_hash:    voteHash,
      note:         'Save your receipt hash to verify your vote was counted'
    });
  } catch (e) {
    console.error('[VOTE CAST]', e);
    res.status(500).json({ error: 'Vote casting failed. Please try again.' });
  }
});

/* ── VOTING STATUS ── */
router.get('/status/:electionId', auth, async (req, res) => {
  try {
    const voted = await q1(
      'SELECT voted_at FROM vote_registry WHERE voter_id=? AND election_id=?',
      [req.user.id, req.params.electionId]
    );
    res.json({ has_voted: !!voted, voted_at: voted?.voted_at || null });
  } catch (e) {
    console.error('[VOTE STATUS]', e);
    res.status(500).json({ error: 'Failed to check voting status' });
  }
});

/* ── VERIFY RECEIPT ── */
router.post('/verify-receipt', auth, async (req, res) => {
  try {
    const { receipt_hash, election_id } = req.body;
    if (!receipt_hash || !election_id)
      return res.status(400).json({ error: 'receipt_hash and election_id are required' });

    const vote = await q1(
      `SELECT v.receipt_hash, v.receipt_sig, v.receipt_data, e.public_key
       FROM votes v JOIN elections e ON v.election_id=e.id
       WHERE v.receipt_hash=? AND v.election_id=?`,
      [receipt_hash, election_id]
    );
    if (!vote) return res.json({ verified: false, message: 'Receipt not found in ballot box' });

    let sigValid = false;
    try {
      sigValid = sigService.verifySignature(vote.receipt_data, vote.receipt_sig, vote.public_key);
    } catch (e) { console.error('[RECEIPT SIG]', e.message); }

    res.json({
      verified:        sigValid,
      signature_valid: sigValid,
      message: sigValid
        ? 'Your vote has been recorded and cryptographically verified'
        : 'Receipt found but signature could not be verified — contact administrator',
      receipt_hash
    });
  } catch (e) {
    console.error('[VERIFY RECEIPT]', e);
    res.status(500).json({ error: 'Receipt verification failed' });
  }
});

/* ── REQUEST VOTER ID RESET ── */
router.post('/request-voter-id-reset', auth, isVoter, async (req, res) => {
  try {
    const { reason } = req.body;

    // Block duplicate pending requests
    const existing = await q1(
      `SELECT id FROM voter_id_reset_requests WHERE user_id=? AND status='pending'`,
      [req.user.id]
    );
    if (existing)
      return res.status(400).json({ error: 'You already have a pending Voter ID reset request. Please wait for admin review.' });

    const user = await q1('SELECT email, full_name FROM users WHERE id=?', [req.user.id]);

    await q('INSERT INTO voter_id_reset_requests (id,user_id,reason) VALUES (?,?,?)',
      [uuid(), req.user.id, reason || null]);

    await sendVoterIdRequestReceived(user.email, user.full_name);

    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'VOTER_ID_RESET_REQUESTED', req.user.id,
       JSON.stringify({ reason }), secUtils.hashIP(req.ip)]);

    res.json({ message: 'Your Voter ID reset request has been submitted. You will be notified by email once reviewed.' });
  } catch (e) {
    console.error('[VOTER ID RESET REQUEST]', e);
    res.status(500).json({ error: 'Failed to submit request. Please try again.' });
  }
});

module.exports = router;
