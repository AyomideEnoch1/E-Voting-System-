require('dotenv').config();
const express = require('express');
const helmet  = require('helmet');
const cors    = require('cors');
const morgan  = require('morgan');
const path    = require('path');
const fs      = require('fs');

const { connectDB }  = require('./database');
const { apiLimiter } = require('./rate-limit.middleware');

const authRoutes      = require('./auth_routes');
const electionRoutes  = require('./election_routes');
const voteRoutes      = require('./vote_routes');
const adminRoutes     = require('./admin_routes');
const candidateRoutes = require('./candidate_routes');

const app  = express();
const PORT = process.env.PORT || 5000;

// FIXED: was '../uploads' — mismatched upload_middleware.js which uses path.join(__dirname,'uploads').
// Both must point to the same directory or stored paths won't resolve to correct URLs.
const uploadsDir = path.join(__dirname, 'uploads');
['photos', 'manifestos', 'documents'].forEach(d => {
  const dir = path.join(uploadsDir, d);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      // FIXED: Helmet sets script-src-attr 'none' by default which blocks ALL inline
      // onclick/onchange/oninput attributes. We've removed every inline handler from
      // admin.html and voter.html and replaced them with addEventListener calls,
      // so this is now set to 'none' safely — no inline handlers remain.
      scriptSrcAttr: ["'none'"],
      styleSrc:      ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
                      "fonts.googleapis.com"],
      imgSrc:        ["'self'", "data:", "blob:"],
      connectSrc:    ["'self'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      fontSrc:       ["'self'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
                      "fonts.googleapis.com", "fonts.gstatic.com"],
      objectSrc:     ["'none'"],
      frameSrc:      ["'none'"]
    }
  }
}));

app.use(cors({
  origin: process.env.CLIENT_URL || `http://localhost:${PORT}`,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.use(express.static(__dirname));
// FIXED: uploadsDir now matches upload_middleware.js BASE_UPLOAD_DIR
app.use('/uploads', express.static(uploadsDir));

app.use('/api', apiLimiter);

app.use('/api/auth',       authRoutes);
app.use('/api/elections',  electionRoutes);
app.use('/api/votes',      voteRoutes);
app.use('/api/admin',      adminRoutes);
app.use('/api/candidates', candidateRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

app.get('/',                  (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register',          (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/voter',             (req, res) => res.sendFile(path.join(__dirname, 'voter.html')));
app.get('/admin',             (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/admin/login',       (req, res) => res.sendFile(path.join(__dirname, 'admin-login.html')));
app.get('/candidate/:id',     (req, res) => res.sendFile(path.join(__dirname, 'candidate-profile.html')));
app.get('/reset-password',    (req, res) => res.sendFile(path.join(__dirname, 'reset-password.html')));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  res.status(500).json({ error: 'Internal server error' });
});

connectDB().then(() => {
  const server = app.listen(PORT, () => console.log(`Server running → http://localhost:${PORT}`));
  server.on('error', err => {
    if (err.code === 'EADDRINUSE') {
      console.error(`❌  Port ${PORT} is already in use.`);
      console.error(`   Run this to fix it: netstat -ano | findstr :${PORT}`);
      console.error(`   Then: taskkill /PID <number> /F`);
      process.exit(1);
    } else {
      throw err;
    }
  });
}).catch(err => { console.error('Startup failed:', err); process.exit(1); });
