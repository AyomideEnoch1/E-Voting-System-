const express      = require('express');
const router       = express.Router();
const { v4: uuid } = require('uuid');
const authMiddleware = require('./auth_middleware');
const encService     = require('./encryption_service');
const keyMgmt        = require('./key-management_service');
const sigService     = require('./digital-signature_service');
const secUtils       = require('./security_utils');
const { q, q1, qa }  = require('./database');

const auth    = authMiddleware.authenticate.bind(authMiddleware);
const isAdmin = authMiddleware.authorize('admin');

/* ── CREATE ── */
router.post('/', auth, isAdmin, async (req, res) => {
  try {
    const { title, description, start_time, end_time } = req.body;
    if (!title || !start_time || !end_time)
      return res.status(400).json({ error: 'title, start_time and end_time are required' });
    if (new Date(end_time) <= new Date(start_time))
      return res.status(400).json({ error: 'end_time must be after start_time' });

    const id = uuid();
    const { publicKey, privateKey } = keyMgmt.generateRSAKeyPair();
    const masterKey    = keyMgmt.generateElectionKey();
    const encMasterKey = encService.encryptWithPassword(masterKey, process.env.KEY_PASSPHRASE || 'default');
    const encPrivKey   = encService.encryptWithPassword(privateKey, process.env.KEY_PASSPHRASE || 'default');

    await q(
      `INSERT INTO elections (id,title,description,start_time,end_time,status,master_key_enc,public_key,created_by)
       VALUES (?,?,?,?,?,'draft',?,?,?)`,
      [id, secUtils.sanitize(title), secUtils.sanitize(description || ''),
       start_time, end_time, JSON.stringify({ masterKey: encMasterKey, privateKey: encPrivKey }),
       publicKey, req.user.id]
    );
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ELECTION_CREATED', req.user.id, JSON.stringify({ electionId: id }), secUtils.hashIP(req.ip)]);

    res.status(201).json({ message: 'Election created', id });
  } catch (e) { console.error('[CREATE ELECTION]', e); res.status(500).json({ error: 'Failed to create election' }); }
});

/* ── UPDATE (draft only) ── */
router.put('/:id', auth, isAdmin, async (req, res) => {
  try {
    const election = await q1('SELECT * FROM elections WHERE id=?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (election.status !== 'draft')
      return res.status(400).json({ error: 'Only draft elections can be edited' });

    const { title, description, start_time, end_time } = req.body;
    if (!title || !start_time || !end_time)
      return res.status(400).json({ error: 'title, start_time and end_time are required' });
    if (new Date(end_time) <= new Date(start_time))
      return res.status(400).json({ error: 'end_time must be after start_time' });

    await q(
      'UPDATE elections SET title=?,description=?,start_time=?,end_time=? WHERE id=?',
      [secUtils.sanitize(title), secUtils.sanitize(description || ''), start_time, end_time, req.params.id]
    );
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ELECTION_UPDATED', req.user.id, JSON.stringify({ electionId: req.params.id }), secUtils.hashIP(req.ip)]);

    res.json({ message: 'Election updated', id: req.params.id });
  } catch (e) { console.error('[UPDATE ELECTION]', e); res.status(500).json({ error: 'Failed to update election' }); }
});

/* ── LIST ── */
router.get('/', auth, async (req, res) => {
  try {
    const elections = await qa(
      `SELECT e.id,e.title,e.description,e.start_time,e.end_time,e.status,
              u.full_name AS created_by_name,
              (SELECT COUNT(*) FROM candidates WHERE election_id=e.id) AS candidate_count,
              (SELECT COUNT(*) FROM vote_registry WHERE election_id=e.id) AS vote_count
       FROM elections e JOIN users u ON e.created_by=u.id ORDER BY e.created_at DESC`
    );
    res.json(elections);
  } catch (e) { console.error('[LIST ELECTIONS]', e); res.status(500).json({ error: 'Failed to fetch elections' }); }
});

/* ── GET ONE ── */
router.get('/:id', auth, async (req, res) => {
  try {
    const election = await q1(
      `SELECT e.id,e.title,e.description,e.start_time,e.end_time,e.status,e.public_key,
              u.full_name AS created_by_name
       FROM elections e JOIN users u ON e.created_by=u.id WHERE e.id=?`,
      [req.params.id]
    );
    if (!election) return res.status(404).json({ error: 'Election not found' });
    const candidates = await qa(
      'SELECT id,name,party,bio,position,photo_url FROM candidates WHERE election_id=? ORDER BY name',
      [req.params.id]
    );
    const voteCount = await q1('SELECT COUNT(*) AS count FROM vote_registry WHERE election_id=?', [req.params.id]);
    res.json({ ...election, candidates, vote_count: voteCount.count });
  } catch (e) { console.error('[GET ELECTION]', e); res.status(500).json({ error: 'Failed to fetch election' }); }
});

/* ── OPEN ── */
router.post('/:id/open', auth, isAdmin, async (req, res) => {
  try {
    const election = await q1('SELECT * FROM elections WHERE id=?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (election.status !== 'draft')
      return res.status(400).json({ error: 'Only draft elections can be opened' });

    // Require at least one candidate before opening
    const candCount = await q1('SELECT COUNT(*) AS cnt FROM candidates WHERE election_id=?', [req.params.id]);
    if (!candCount || candCount.cnt < 1)
      return res.status(400).json({ error: 'Add at least one candidate before opening the election' });

    await q("UPDATE elections SET status='active' WHERE id=?", [req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ELECTION_OPENED', req.user.id, JSON.stringify({ electionId: req.params.id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'Election is now active and open for voting' });
  } catch (e) { console.error('[OPEN ELECTION]', e); res.status(500).json({ error: 'Failed to open election' }); }
});

/* ── CLOSE ── */
router.post('/:id/close', auth, isAdmin, async (req, res) => {
  try {
    const election = await q1('SELECT * FROM elections WHERE id=?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (election.status !== 'active')
      return res.status(400).json({ error: 'Only active elections can be closed' });
    await q("UPDATE elections SET status='closed' WHERE id=?", [req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ELECTION_CLOSED', req.user.id, JSON.stringify({ electionId: req.params.id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'Election closed. Run tally to publish results.' });
  } catch (e) { console.error('[CLOSE ELECTION]', e); res.status(500).json({ error: 'Failed to close election' }); }
});

/* ── TALLY ── */
router.post('/:id/tally', auth, isAdmin, async (req, res) => {
  try {
    const election = await q1('SELECT * FROM elections WHERE id=?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (election.status !== 'closed')
      return res.status(400).json({ error: 'Election must be closed before tallying' });

    const keyData   = JSON.parse(election.master_key_enc);
    const masterKey = encService.decryptWithPassword(
      keyData.masterKey.encrypted, process.env.KEY_PASSPHRASE || 'default',
      keyData.masterKey.salt, keyData.masterKey.iv, keyData.masterKey.tag
    );

    const votes      = await qa('SELECT * FROM votes WHERE election_id=?', [req.params.id]);
    const candidates = await qa('SELECT * FROM candidates WHERE election_id=?', [req.params.id]);
    const tally      = {};
    candidates.forEach(c => { tally[c.id] = { name: c.name, party: c.party, votes: 0 }; });

    let invalidVotes = 0;
    for (const vote of votes) {
      try {
        const cid = encService.decryptVote({ encrypted: vote.encrypted_vote, iv: vote.vote_iv, tag: vote.vote_tag }, masterKey);
        if (tally[cid] !== undefined) tally[cid].votes++;
        else invalidVotes++;
      } catch { invalidVotes++; }
    }

    const totalVotes = votes.length;
    const results = {
      electionId: election.id, electionTitle: election.title,
      talliedAt: new Date().toISOString(), totalVotes, invalidVotes,
      candidates: Object.entries(tally).map(([id, d]) => ({
        id, ...d, percentage: totalVotes ? ((d.votes / totalVotes) * 100).toFixed(2) : '0.00'
      })).sort((a, b) => b.votes - a.votes)
    };

    const privKeyData = keyData.privateKey;
    const privateKey  = encService.decryptWithPassword(
      privKeyData.encrypted, process.env.KEY_PASSPHRASE || 'default',
      privKeyData.salt, privKeyData.iv, privKeyData.tag
    );
    const { data: signedResultsStr, signature } = sigService.signElectionResults(results, privateKey);

    // Store the exact string that was signed — guarantees verifySignature will match on retrieval
    await q('INSERT INTO election_results (id,election_id,results,signature,tallied_by) VALUES (?,?,?,?,?)',
      [uuid(), election.id, signedResultsStr, signature, req.user.id]);
    await q("UPDATE elections SET status='tallied',results_sig=? WHERE id=?", [signature, election.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ELECTION_TALLIED', req.user.id, JSON.stringify({ electionId: election.id, totalVotes }), secUtils.hashIP(req.ip)]);

    res.json({ message: 'Tally complete', results, signature });
  } catch (e) { console.error('[TALLY]', e); res.status(500).json({ error: 'Tally failed' }); }
});

/* ── RESULTS ── */
router.get('/:id/results', auth, async (req, res) => {
  try {
    const result = await q1(
      `SELECT r.*,u.full_name AS tallied_by_name FROM election_results r
       JOIN users u ON r.tallied_by=u.id WHERE r.election_id=?`,
      [req.params.id]
    );
    if (!result) return res.status(404).json({ error: 'Results not yet available' });
    const election = await q1('SELECT public_key FROM elections WHERE id=?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    // result.results is the raw JSON string — verify against that exact string as it was signed
    const isValid = sigService.verifySignature(result.results, result.signature, election.public_key);
    res.json({
      results:          JSON.parse(result.results),
      signature:        result.signature,
      signature_valid:  isValid,
      tallied_by:       result.tallied_by_name,
      tallied_at:       result.tallied_at
    });
  } catch (e) { console.error('[GET RESULTS]', e); res.status(500).json({ error: 'Failed to fetch results' }); }
});

/* ── ADD CANDIDATE (shortcut) ── */
router.post('/:id/candidates', auth, isAdmin, async (req, res) => {
  try {
    const { name, party, bio, position } = req.body;
    if (!name) return res.status(400).json({ error: 'Candidate name required' });
    const election = await q1('SELECT status FROM elections WHERE id=?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (['active','closed','tallied'].includes(election.status))
      return res.status(400).json({ error: 'Cannot add candidates to an active or closed election' });
    const id = uuid();
    await q('INSERT INTO candidates (id,election_id,name,party,bio,position) VALUES (?,?,?,?,?,?)',
      [id, req.params.id, secUtils.sanitize(name), secUtils.sanitize(party||''), secUtils.sanitize(bio||''), secUtils.sanitize(position||'')]);
    res.status(201).json({ message: 'Candidate added', id });
  } catch (e) { console.error('[ADD CANDIDATE]', e); res.status(500).json({ error: 'Failed to add candidate' }); }
});

/* ── DELETE ELECTION ── */
router.delete('/:id', auth, isAdmin, async (req, res) => {
  try {
    const election = await q1('SELECT * FROM elections WHERE id=?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });

    // Block deletion of active elections — too dangerous
    if (election.status === 'active')
      return res.status(400).json({ error: 'Cannot delete an active election. Close it first.' });

    // Cascade delete in correct FK order
    await q('DELETE FROM election_results WHERE election_id=?', [req.params.id]);
    await q('DELETE FROM vote_registry   WHERE election_id=?', [req.params.id]);
    await q('DELETE FROM votes           WHERE election_id=?', [req.params.id]);
    await q('DELETE FROM candidates      WHERE election_id=?', [req.params.id]);
    await q('DELETE FROM elections       WHERE id=?',          [req.params.id]);

    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'ELECTION_DELETED', req.user.id,
       JSON.stringify({ electionId: req.params.id, title: election.title }), secUtils.hashIP(req.ip)]);

    res.json({ message: `Election "${election.title}" deleted successfully` });
  } catch (e) {
    console.error('[DELETE ELECTION]', e);
    res.status(500).json({ error: 'Failed to delete election' });
  }
});

module.exports = router;

