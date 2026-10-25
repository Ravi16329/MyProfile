require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const admin = require('firebase-admin');
const { Resend } = require('resend');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set and at least 32 characters long.');
}
if (!process.env.FRONTEND_URL) throw new Error('FRONTEND_URL is required.');
if (!process.env.RESEND_API_KEY) throw new Error('RESEND_API_KEY is required.');
if (!process.env.EMAIL_FROM) throw new Error('EMAIL_FROM is required.');

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON || '{}');
} catch {
  throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON must be valid JSON on one line.');
}
if (!serviceAccount.project_id || !serviceAccount.private_key || !serviceAccount.client_email) {
  throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON must contain a Firebase Admin service-account JSON object.');
}
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const resend = new Resend(process.env.RESEND_API_KEY);

app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '20kb' }));
app.use(cors({
<<<<<<< HEAD
  origin: "https://ravi16329.github.io",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
=======
  origin(origin, callback) {
    // Allow no-origin clients for health checks/curl; browser requests must match configured frontend.
    if (!origin || origin === process.env.FRONTEND_URL) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
>>>>>>> 68918d054ca096944e4e536314844cdde738bf19
}));

const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });

// Temporary challenges live in memory to avoid a database. Render restarts clear pending OTPs.
// Use one instance for this no-database version; for durable/multi-instance production use Redis or a DB.
const challenges = new Map();
const sessions = new Map();
const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const SESSION_TTL_MS = 60 * 60 * 1000;
const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
const safeEqual = (a, b) => {
  const aa = Buffer.from(a, 'hex'); const bb = Buffer.from(b, 'hex');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}
function signSession(uid, email) {
  // HMAC-signed compact token; no external JWT dependency required.
  const payload = Buffer.from(JSON.stringify({ uid, email, exp: Date.now() + SESSION_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.'); if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(parts[0]).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts[1]))) return null;
  try { const p = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); return p.exp > Date.now() ? p : null; }
  catch { return null; }
}
async function requireFirebaseUser(req, res, next) {
  try {
    const token = bearer(req);
    if (!token) return res.status(401).json({ error: 'Firebase ID token is required.' });
    req.firebaseUser = await admin.auth().verifyIdToken(token, true);
    if (!req.firebaseUser.email || req.firebaseUser.email_verified !== true) {
      return res.status(403).json({ error: 'Verify your email address in Firebase before using email MFA.' });
    }
    next();
  } catch {
    return res.status(401).json({ error: 'Firebase session is invalid or expired. Please sign in again.' });
  }
}

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Called after the frontend signs in with Firebase email/password.
app.post('/api/auth/request-otp', otpLimiter, requireFirebaseUser, async (req, res) => {
  const uid = req.firebaseUser.uid;
  const email = req.firebaseUser.email.toLowerCase();
  // Remove any earlier challenge for this user before creating a new one.
  challenges.delete(uid);
  const code = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
  const challengeId = crypto.randomBytes(24).toString('hex');
  const createdAt = Date.now();
  const expiresAt = createdAt + OTP_TTL_MS;
  try {
    const { error } = await resend.emails.send({
      from: process.env.EMAIL_FROM,
      to: [email],
      subject: 'Your MyProfile login verification code',
      text: `Your MyProfile verification code is ${code}. It expires in 5 minutes. If you did not try to sign in, you can ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto"><h2>MyProfile login verification</h2><p>Enter this code to finish signing in:</p><p style="font-size:32px;letter-spacing:8px;font-weight:bold">${code}</p><p>This code expires in <b>5 minutes</b>. Never share it with anyone.</p><p>If you did not try to sign in, you can ignore this email.</p></div>`,
    });
    if (error) {
      console.error('Resend send error:', error.message || error.name || 'unknown');
      return res.status(502).json({ error: 'Email delivery failed. Check your Resend sender/domain configuration.' });
    }
    challenges.set(uid, { challengeId, email, codeHash: hash(code), createdAt, expiresAt, attempts: 0 });
    return res.json({ message: 'Verification code sent.', challengeId, expiresInSeconds: 300 });
  } catch (e) {
    console.error('Email provider error:', e.message);
    return res.status(502).json({ error: 'Unable to send verification email right now.' });
  }
});

app.post('/api/auth/verify-otp', verifyLimiter, requireFirebaseUser, (req, res) => {
  const { code, challengeId } = req.body || {};
  if (typeof code !== 'string' || !/^\d{6}$/.test(code) || typeof challengeId !== 'string') {
    return res.status(400).json({ error: 'Enter the six-digit code from your email.' });
  }
  const uid = req.firebaseUser.uid;
  const challenge = challenges.get(uid);
  if (!challenge || challenge.challengeId !== challengeId) return res.status(400).json({ error: 'Code not found. Request a new code.' });
  if (Date.now() > challenge.expiresAt) { challenges.delete(uid); return res.status(400).json({ error: 'Code expired. Request a new code.' }); }
  challenge.attempts += 1;
  if (challenge.attempts > MAX_ATTEMPTS) { challenges.delete(uid); return res.status(429).json({ error: 'Too many incorrect attempts. Request a new code.' }); }
  if (!safeEqual(hash(code), challenge.codeHash)) return res.status(400).json({ error: 'Incorrect code. Please try again.' });
  challenges.delete(uid); // one-time use
  const sessionToken = signSession(uid, challenge.email);
  sessions.set(hash(sessionToken), { uid, expiresAt: Date.now() + SESSION_TTL_MS });
  return res.json({ message: 'MFA verified. Login successful.', sessionToken, expiresInSeconds: 3600 });
});

// Use this endpoint to protect backend resources after MFA.
app.get('/api/auth/session', (req, res) => {
  const session = verifySessionToken(bearer(req));
  if (!session || !sessions.has(hash(bearer(req)))) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, uid: session.uid, email: session.email, expiresAt: session.exp });
});
app.post('/api/auth/logout', (req, res) => {
  const token = bearer(req);
  if (token) sessions.delete(hash(token));
  return res.json({ message: 'Logged out.' });
});

// Avoid leaking stack traces or provider credentials.
app.use((err, _req, res, _next) => {
  if (err.message === 'Origin not allowed by CORS') return res.status(403).json({ error: 'Origin not allowed.' });
  console.error('Unhandled server error:', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// Expire in-memory state periodically.
setInterval(() => {
  const now = Date.now();
  for (const [uid, challenge] of challenges) if (challenge.expiresAt < now) challenges.delete(uid);
  for (const [key, session] of sessions) if (session.expiresAt < now) sessions.delete(key);
}, 60_000).unref();

app.listen(PORT, () => console.log(`MyProfile MFA API listening on port ${PORT}`));
