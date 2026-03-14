const express        = require('express');
const router         = express.Router();
const { v4: uuid }   = require('uuid');
const path           = require('path');
const fs             = require('fs');
const authMiddleware = require('./auth_middleware');
const { uploadPhoto, uploadManifesto, uploadDocuments, BASE_UPLOAD_DIR } = require('./upload_middleware');
const secUtils       = require('./security_utils');
const { q, q1, qa }  = require('./database');

const auth    = authMiddleware.authenticate.bind(authMiddleware);
const isAdmin = authMiddleware.authorize('admin');

function fileUrl(filePath) {
  if (!filePath) return null;
  // Convert absolute storage path to a web URL.
  // Use BASE_UPLOAD_DIR from upload_middleware (the single source of truth for storage location).
  if (filePath.startsWith(BASE_UPLOAD_DIR)) {
    return '/uploads/' + path.relative(BASE_UPLOAD_DIR, filePath).replace(/\\/g, '/');
  }
  // Fallback: just return the basename
  return '/uploads/' + path.basename(filePath);
}

// Safe JSON parse — returns fallback value instead of throwing on malformed data
function safeJsonParse(str, fallback = []) {
  if (!str) return fallback;
  try { return JSON.parse(str); } catch { return fallback; }
}

/* ═══════════════════════════════════════════
   SPECIFIC /profile/:id routes MUST come
   BEFORE the wildcard /:electionId routes.
   ═══════════════════════════════════════════ */

/* ── GET CANDIDATE PROFILE ── */
router.get('/profile/:id', auth, async (req, res) => {
  try {
    const c = await q1('SELECT * FROM candidates WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Candidate not found' });
    res.json({
      ...c,
      photo_url:     c.photo_url     ? fileUrl(c.photo_url)     : null,
      manifesto_doc: c.manifesto_doc ? fileUrl(c.manifesto_doc) : null,
      extra_docs:    safeJsonParse(c.extra_docs).map(f => ({ name: f.name, url: fileUrl(f.path) }))
    });
  } catch (e) {
    console.error('[GET PROFILE]', e);
    res.status(500).json({ error: 'Failed to fetch candidate' });
  }
});

/* ── UPDATE CANDIDATE PROFILE ── */
router.put('/profile/:id', auth, isAdmin, async (req, res) => {
  try {
    const c = await q1('SELECT id FROM candidates WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Candidate not found' });
    const { name, party, position, age, gender, state_of_origin, education, experience, bio, manifesto, sort_order } = req.body;
    await q(
      `UPDATE candidates SET name=?,party=?,position=?,age=?,gender=?,state_of_origin=?,
         education=?,experience=?,bio=?,manifesto=?,sort_order=? WHERE id=?`,
      [secUtils.sanitize(name || ''), secUtils.sanitize(party || ''), secUtils.sanitize(position || ''),
       age ? +age : null, secUtils.sanitize(gender || ''), secUtils.sanitize(state_of_origin || ''),
       secUtils.sanitize(education || ''), secUtils.sanitize(experience || ''),
       secUtils.sanitize(bio || ''), manifesto || '', sort_order ? +sort_order : 0, req.params.id]
    );
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'CANDIDATE_UPDATED', req.user.id, JSON.stringify({ candidateId: req.params.id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'Candidate updated', candidate: await q1('SELECT * FROM candidates WHERE id=?', [req.params.id]) });
  } catch (e) {
    console.error('[UPDATE CANDIDATE]', e);
    res.status(500).json({ error: 'Failed to update candidate' });
  }
});

/* ── UPLOAD PHOTO ── */
router.post('/profile/:id/photo', auth, isAdmin, uploadPhoto, async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
    const c = await q1('SELECT id, photo_url FROM candidates WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Candidate not found' });
    if (c.photo_url && fs.existsSync(c.photo_url)) try { fs.unlinkSync(c.photo_url); } catch {}
    await q('UPDATE candidates SET photo_url=? WHERE id=?', [req.file.path, req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'CANDIDATE_PHOTO_UPLOADED', req.user.id, JSON.stringify({ candidateId: req.params.id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'Photo uploaded', photo_url: fileUrl(req.file.path) });
  } catch (e) {
    console.error('[PHOTO]', e);
    res.status(500).json({ error: 'Photo upload failed' });
  }
});

/* ── UPLOAD MANIFESTO ── */
router.post('/profile/:id/manifesto', auth, isAdmin, uploadManifesto, async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const c = await q1('SELECT id, manifesto_doc FROM candidates WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Candidate not found' });
    if (c.manifesto_doc && fs.existsSync(c.manifesto_doc)) try { fs.unlinkSync(c.manifesto_doc); } catch {}
    await q('UPDATE candidates SET manifesto_doc=? WHERE id=?', [req.file.path, req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'CANDIDATE_MANIFESTO_UPLOADED', req.user.id, JSON.stringify({ candidateId: req.params.id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'Manifesto uploaded', manifesto_doc: fileUrl(req.file.path) });
  } catch (e) {
    console.error('[MANIFESTO]', e);
    res.status(500).json({ error: 'Upload failed' });
  }
});

/* ── UPLOAD DOCUMENTS ── */
router.post('/profile/:id/documents', auth, isAdmin, uploadDocuments, async (req, res) => {
  try {
    if (!req.files || !req.files.length) return res.status(400).json({ error: 'No documents uploaded' });
    const c = await q1('SELECT id, extra_docs FROM candidates WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Candidate not found' });
    const existing = safeJsonParse(c.extra_docs);
    const newDocs  = req.files.map(f => ({
      name: f.originalname, path: f.path, filename: f.filename,
      size: f.size, uploaded_at: new Date().toISOString()
    }));
    const merged = [...existing, ...newDocs].slice(0, 3);
    await q('UPDATE candidates SET extra_docs=? WHERE id=?', [JSON.stringify(merged), req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'CANDIDATE_DOCS_UPLOADED', req.user.id,
       JSON.stringify({ candidateId: req.params.id, count: newDocs.length }), secUtils.hashIP(req.ip)]);
    res.json({ message: `${newDocs.length} document(s) uploaded`, extra_docs: merged.map(f => ({ name: f.name, url: fileUrl(f.path) })) });
  } catch (e) {
    console.error('[DOCS]', e);
    res.status(500).json({ error: 'Upload failed' });
  }
});

/* ── DELETE DOCUMENT ── */
router.delete('/profile/:id/documents/:filename', auth, isAdmin, async (req, res) => {
  try {
    const c = await q1('SELECT id, extra_docs FROM candidates WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Candidate not found' });
    const docs   = safeJsonParse(c.extra_docs);
    const target = docs.find(d => d.filename === req.params.filename);
    if (!target) return res.status(404).json({ error: 'Document not found' });
    if (fs.existsSync(target.path)) try { fs.unlinkSync(target.path); } catch {}
    const updated = docs.filter(d => d.filename !== req.params.filename);
    await q('UPDATE candidates SET extra_docs=? WHERE id=?', [JSON.stringify(updated), req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'CANDIDATE_DOC_DELETED', req.user.id,
       JSON.stringify({ candidateId: req.params.id, filename: req.params.filename }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'Document deleted', remaining: updated.length });
  } catch (e) {
    console.error('[DELETE DOC]', e);
    res.status(500).json({ error: 'Failed to delete document' });
  }
});

/* ── DELETE CANDIDATE ── */
router.delete('/profile/:id', auth, isAdmin, async (req, res) => {
  try {
    const c = await q1(
      `SELECT c.*, e.status AS election_status
       FROM candidates c JOIN elections e ON c.election_id=e.id WHERE c.id=?`,
      [req.params.id]
    );
    if (!c) return res.status(404).json({ error: 'Candidate not found' });
    if (['active', 'closed', 'tallied'].includes(c.election_status))
      return res.status(400).json({ error: 'Cannot delete candidate from an active or closed election' });

    if (c.photo_url     && fs.existsSync(c.photo_url))     try { fs.unlinkSync(c.photo_url); }     catch {}
    if (c.manifesto_doc && fs.existsSync(c.manifesto_doc)) try { fs.unlinkSync(c.manifesto_doc); } catch {}
    safeJsonParse(c.extra_docs).forEach(d => { if (fs.existsSync(d.path)) try { fs.unlinkSync(d.path); } catch {} });

    await q('DELETE FROM candidates WHERE id=?', [req.params.id]);
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'CANDIDATE_DELETED', req.user.id, JSON.stringify({ candidateId: req.params.id }), secUtils.hashIP(req.ip)]);
    res.json({ message: 'Candidate deleted' });
  } catch (e) {
    console.error('[DELETE CANDIDATE]', e);
    res.status(500).json({ error: 'Failed to delete candidate' });
  }
});

/* ═══════════════════════════════════════════
   WILDCARD routes — must stay LAST
   ═══════════════════════════════════════════ */

/* ── ADD CANDIDATE TO ELECTION ── */
router.post('/:electionId', auth, isAdmin, async (req, res) => {
  try {
    const { electionId } = req.params;
    const { name, party, position, age, gender, state_of_origin, education, experience, bio, manifesto } = req.body;
    if (!name) return res.status(400).json({ error: 'Candidate name is required' });

    const election = await q1('SELECT id, status FROM elections WHERE id=?', [electionId]);
    if (!election) return res.status(404).json({ error: 'Election not found' });
    if (['active', 'closed', 'tallied'].includes(election.status))
      return res.status(400).json({ error: 'Cannot add candidates to an active or closed election' });

    const id = uuid();
    await q(
      `INSERT INTO candidates
         (id, election_id, name, party, position, age, gender, state_of_origin, education, experience, bio, manifesto)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [id, electionId, secUtils.sanitize(name), secUtils.sanitize(party || ''),
       secUtils.sanitize(position || ''), age ? +age : null, secUtils.sanitize(gender || ''),
       secUtils.sanitize(state_of_origin || ''), secUtils.sanitize(education || ''),
       secUtils.sanitize(experience || ''), secUtils.sanitize(bio || ''), manifesto || '']
    );
    await q('INSERT INTO audit_log (id,action,user_id,meta,ip_hash) VALUES (?,?,?,?,?)',
      [uuid(), 'CANDIDATE_CREATED', req.user.id,
       JSON.stringify({ candidateId: id, electionId }), secUtils.hashIP(req.ip)]);

    res.status(201).json({ message: 'Candidate created', candidate: await q1('SELECT * FROM candidates WHERE id=?', [id]) });
  } catch (e) {
    console.error('[CREATE CANDIDATE]', e);
    res.status(500).json({ error: 'Failed to create candidate' });
  }
});

/* ── LIST CANDIDATES FOR ELECTION ── */
router.get('/:electionId', auth, async (req, res) => {
  try {
    const candidates = await qa(
      `SELECT id, name, party, position, age, gender, state_of_origin, education, experience,
              bio, manifesto, photo_url, manifesto_doc, extra_docs, sort_order, created_at
       FROM candidates WHERE election_id=? ORDER BY sort_order ASC, name ASC`,
      [req.params.electionId]
    );
    res.json(candidates.map(c => ({
      ...c,
      photo_url:     c.photo_url     ? fileUrl(c.photo_url)     : null,
      manifesto_doc: c.manifesto_doc ? fileUrl(c.manifesto_doc) : null,
      extra_docs:    safeJsonParse(c.extra_docs).map(f => ({ name: f.name, url: fileUrl(f.path) }))
    })));
  } catch (e) {
    console.error('[LIST CANDIDATES]', e);
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});

module.exports = router;
