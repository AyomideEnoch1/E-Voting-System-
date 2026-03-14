/**
 * Rate Limiting Middleware
 * - General API limiter (100 req / 15 min)
 * - Strict auth limiter (10 req / 15 min) — prevents brute force
 * - Vote limiter (1 vote per voter per election — enforced at DB level too)
 */

const rateLimit = require('express-rate-limit');

/** General API rate limiter */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please try again after 15 minutes' }
});

/** Strict limiter for login/register (brute-force protection) */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts — please wait 15 minutes' }
});

/** Vote submission limiter */
const voteLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 5, // Max 5 vote attempts per IP (duplicate vote prevention at network level)
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many vote attempts — please contact the administrator' }
});

module.exports = { apiLimiter, authLimiter, voteLimiter };
