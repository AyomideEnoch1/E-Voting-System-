const express        = require('express');
const router         = express.Router();
const authMiddleware = require('./auth_middleware');
const { q1, qa }     = require('./database');
const liveEvents     = require('./live_events');

const auth       = authMiddleware.authenticate.bind(authMiddleware);
const isObserver = authMiddleware.authorize('observer', 'admin', 'superadmin');

/* ── STATS ── */
router.get('/stats', auth, isObserver, async (req, res) => {
  try {
    const [[{ totalElections }]]  = await require('./database').q('SELECT COUNT(*) AS totalElections FROM elections');
    const [[{ totalVotes }]]      = await require('./database').q('SELECT COUNT(*) AS totalVotes FROM vote_registry');
    const [[{ activeElections }]] = await require('./database').q("SELECT COUNT(*) AS activeElections FROM elections WHERE status='active'");
    const [[{ talliedElections }]]= await require('./database').q("SELECT COUNT(*) AS talliedElections FROM elections WHERE status='tallied'");
    res.json({ totalElections, totalVotes, activeElections, talliedElections });
  } catch (e) { console.error('[OBSERVER STATS]', e); res.status(500).json({ error: 'Failed to fetch stats' }); }
});

/* ── LIST ELECTIONS ── */
router.get('/elections', auth, isObserver, async (req, res) => {
  try {
    const elections = await qa(
      `SELECT e.id, e.title, e.description, e.start_time, e.end_time, e.status,
              u.full_name AS created_by_name,
              (SELECT COUNT(*) FROM candidates  WHERE election_id = e.id) AS candidate_count,
              (SELECT COUNT(*) FROM vote_registry WHERE election_id = e.id) AS vote_count
       FROM elections e JOIN users u ON e.created_by = u.id
       ORDER BY e.created_at DESC`
    );
    res.json(elections);
  } catch (e) { console.error('[OBSERVER LIST]', e); res.status(500).json({ error: 'Failed to fetch elections' }); }
});

/* ── GET ONE ELECTION ── */
router.get('/elections/:id', auth, isObserver, async (req, res) => {
  try {
    const election = await q1(
      `SELECT e.id, e.title, e.description, e.start_time, e.end_time, e.status, e.public_key,
              u.full_name AS created_by_name
       FROM elections e JOIN users u ON e.created_by = u.id WHERE e.id = ?`,
      [req.params.id]
    );
    if (!election) return res.status(404).json({ error: 'Election not found' });

    const candidates = await qa(
      'SELECT id, name, party, bio, position, photo_url FROM candidates WHERE election_id = ? ORDER BY sort_order, name',
      [req.params.id]
    );
    const [[{ vote_count }]] = await require('./database').q(
      'SELECT COUNT(*) AS vote_count FROM vote_registry WHERE election_id = ?', [req.params.id]
    );
    res.json({ ...election, candidates, vote_count });
  } catch (e) { console.error('[OBSERVER GET]', e); res.status(500).json({ error: 'Failed to fetch election' }); }
});

/* ── RESULTS ── */
router.get('/elections/:id/results', auth, isObserver, async (req, res) => {
  try {
    const election = await q1('SELECT status, public_key FROM elections WHERE id = ?', [req.params.id]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (election.status !== 'tallied') return res.status(400).json({ error: 'Results are not yet available' });

    const result = await q1(
      `SELECT r.*, u.full_name AS tallied_by_name
       FROM election_results r JOIN users u ON r.tallied_by = u.id WHERE r.election_id = ?`,
      [req.params.id]
    );
    if (!result) return res.status(404).json({ error: 'Results not found' });

    const sigService = require('./digital-signature_service');
    const isValid    = sigService.verifySignature(result.results, result.signature, election.public_key);

    res.json({
      results:         JSON.parse(result.results),
      signature:       result.signature,
      signature_valid: isValid,
      tallied_by:      result.tallied_by_name,
      tallied_at:      result.tallied_at
    });
  } catch (e) { console.error('[OBSERVER RESULTS]', e); res.status(500).json({ error: 'Failed to fetch results' }); }
});

/* ── REAL-TIME VOTE COUNT (SSE) ── */
// GET /api/observer/elections/:id/live
// Streams vote count updates whenever a new vote is cast.
router.get('/elections/:id/live', auth, isObserver, async (req, res) => {
  const electionId = req.params.id;

  res.set({
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no'       // disable nginx buffering
  });
  res.flushHeaders();

  // Send initial count immediately
  const sendCount = async () => {
    try {
      const [[{ vote_count }]] = await require('./database').q(
        'SELECT COUNT(*) AS vote_count FROM vote_registry WHERE election_id = ?', [electionId]
      );
      const [[{ candidate_count }]] = await require('./database').q(
        'SELECT COUNT(*) AS candidate_count FROM candidates WHERE election_id = ?', [electionId]
      );
      res.write(`data: ${JSON.stringify({ vote_count, candidate_count, electionId })}\n\n`);
    } catch (e) {
      console.error('[OBSERVER SSE]', e);
    }
  };

  await sendCount();

  // Push updates on every live event
  const onUpdate = (payload) => {
    if (payload.type === 'VOTE_CAST' || payload.type === 'ELECTION_CHANGED') {
      if (!payload.electionId || payload.electionId === electionId) {
        sendCount();
      }
    }
  };

  liveEvents.on('update', onUpdate);

  // Heartbeat every 25s to keep the connection alive through proxies
  const heartbeat = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, 25000);

  req.on('close', () => {
    liveEvents.off('update', onUpdate);
    clearInterval(heartbeat);
  });
});

module.exports = router;
