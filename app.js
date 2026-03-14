require('dotenv').config();
const express = require('express');
const helmet  = require('helmet');
const cors    = require('cors');
const morgan  = require('morgan');
const path    = require('path');
const fs      = require('fs');

const { connectDB }  = require('./database');
const { apiLimiter } = require('./rate-limit_middleware');

const authRoutes      = require('./auth_routes');
const electionRoutes  = require('./election_routes');
const voteRoutes      = require('./vote_routes');
const adminRoutes     = require('./admin_routes');
const candidateRoutes = require('./candidate_routes');

const app  = express();
const PORT = process.env.PORT || 5000;

const uploadsDir = path.join(__dirname, 'uploads');
['photos', 'manifestos', 'documents'].forEach(d => {
  const dir = path.join(uploadsDir, d);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      styleSrc:   ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
      imgSrc:     ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      fontSrc:    ["'self'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.gstatic.com"],
      objectSrc:  ["'none'"],
      frameSrc:   ["'none'"]
    }
  }
}));

app.use(cors({
  origin: process.env.CLIENT_URL || true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.use(express.static(__dirname));
app.use('/uploads', express.static(uploadsDir));

app.use('/api', apiLimiter);

app.use('/api/auth',       authRoutes);
app.use('/api/elections',  electionRoutes);
app.use('/api/votes',      voteRoutes);
app.use('/api/admin',      adminRoutes);
app.use('/api/candidates', candidateRoutes);

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

app.get('/',                  (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/landing',           (req, res) => res.sendFile(path.join(__dirname, 'landing.html')));
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
  app.listen(PORT, () => console.log(`Server running → http://localhost:${PORT}`));
}).catch(err => { console.error('Startup failed:', err); process.exit(1); });
