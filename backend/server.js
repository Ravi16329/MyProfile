
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const admin = require('firebase-admin');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;

const FRONTEND_URL = process.env.FRONTEND_URL;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM;

// --------------------------------------------------
// 1. Validate environment variables
// --------------------------------------------------

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be set and at least 32 characters long.');
}

if (!FRONTEND_URL) {
  throw new Error('FRONTEND_URL is required.');
}

if (!RESEND_API_KEY) {
  throw new Error('RESEND_API_KEY is required.');
}

if (!EMAIL_FROM) {
  throw new Error('EMAIL_FROM is required.');
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON || '{}'
  );
} catch {
  throw new Error(
    'FIREBASE_SERVICE_ACCOUNT_JSON must contain valid JSON.'
  );
}

if (
  !serviceAccount.project_id ||
  !serviceAccount.private_key ||
  !serviceAccount.client_email
) {
  throw new Error(
    'Firebase service account must contain project_id, private_key, and client_email.'
  );
}

// --------------------------------------------------
// 2. Initialize Firebase Admin and Resend
// --------------------------------------------------

admin.initializeApp({
  credential: admin.credential.cert({
    ...serviceAccount,
    private_key: serviceAccount.private_key.replace(/\\n/g, '\n')
  })
});

const resend = new Resend(RESEND_API_KEY);

// --------------------------------------------------
// 3. Middleware and CORS
// --------------------------------------------------

app.set('trust proxy', 1);

app.use(helmet());

app.use(express.json({ limit: '20kb' }));

const allowedOrigin = new URL(FRONTEND_URL).origin;

app.use(cors({
  origin(origin, callback) {
    // Permit requests without an Origin header, such as health checks.
    if (!origin) {
      return callback(null, true);
    }

    if (origin === allowedOrigin) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
}));

// --------------------------------------------------
// 4. Rate limits
// --------------------------------------------------

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

// --------------------------------------------------
// 5. In-memory challenges and sessions
// --------------------------------------------------

// Pending OTPs and sessions are cleared when the server restarts.
// This version does not require a database.

const challenges = new Map();
const sessions = new Map();

const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const SESSION_TTL_MS = 60 * 60 * 1000;

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b)) {
    return false;
  }

  const aa = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');

  return (
    aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb)
  );
}

function bearer(req) {
  const header = req.headers.authorization || '';

  return header.startsWith('Bearer ')
    ? header.slice(7)
    : null;
}

// --------------------------------------------------
// 6. Create and verify application session tokens
// --------------------------------------------------

function signSession(uid, email) {
  const payload = Buffer.from(
    JSON.stringify({
      uid,
      email,
      exp: Date.now() + SESSION_TTL_MS
    })
  ).toString('base64url');

  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');

  return `${payload}.${signature}`;
}

function verifySessionToken(token) {
  if (typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');

  if (parts.length !== 2) {
    return null;
  }

  const [payload, signature] = parts;

  const expectedSignature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');

  const expectedBuffer = Buffer.from(expectedSignature);
  const actualBuffer = Buffer.from(signature);

  if (
    actualBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, 'base64url').toString()
    );

    if (
      !data.uid ||
      !data.email ||
      typeof data.exp !== 'number' ||
      data.exp <= Date.now()
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

// --------------------------------------------------
// 7. Firebase ID token verification middleware
// --------------------------------------------------

async function requireFirebaseUser(req, res, next) {
  try {
    const token = bearer(req);

    if (!token) {
      return res.status(401).json({
        error: 'Firebase ID token is required.'
      });
    }

    const decodedToken = await admin
      .auth()
      .verifyIdToken(token, true);

    if (
      !decodedToken.email ||
      decodedToken.email_verified !== true
    ) {
      return res.status(403).json({
        error: 'Verify your email address before using email MFA.'
      });
    }

    req.firebaseUser = decodedToken;

    return next();
  } catch (error) {
    console.error(
      'Firebase token verification failed:',
      error.message
    );

    return res.status(401).json({
      error: 'Firebase session is invalid or expired. Please sign in again.'
    });
  }
}

// --------------------------------------------------
// 8. Health endpoint
// --------------------------------------------------

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// --------------------------------------------------
// 9. Request an email OTP
// --------------------------------------------------

app.post(
  '/api/auth/request-otp',
  otpLimiter,
  requireFirebaseUser,
  async (req, res) => {
    const uid = req.firebaseUser.uid;
    const email = req.firebaseUser.email.toLowerCase();

    // Invalidate an earlier OTP for this user.
    challenges.delete(uid);

    const code = crypto
      .randomInt(0, 1000000)
      .toString()
      .padStart(6, '0');

    const challengeId = crypto
      .randomBytes(24)
      .toString('hex');

    const createdAt = Date.now();
    const expiresAt = createdAt + OTP_TTL_MS;

    try {
      const { data, error } = await resend.emails.send({
        from: EMAIL_FROM,
        to: [email],
        subject: 'Your MyProfile login verification code',

        text:
          `Your MyProfile verification code is ${code}. ` +
          'It expires in 5 minutes. If you did not try to sign in, ignore this email.',

        html: `
          <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto">
            <h2>MyProfile login verification</h2>
            <p>Enter this code to finish signing in:</p>
            <p style="font-size:32px;letter-spacing:8px;font-weight:bold">
              ${code}
            </p>
            <p>This code expires in <b>5 minutes</b>.</p>
            <p>Never share this code with anyone.</p>
            <p>If you did not try to sign in, ignore this email.</p>
          </div>
        `
      });

      if (error || !data) {
        console.error(
          'Resend send error:',
          error?.message || 'No email response returned.'
        );

        return res.status(502).json({
          error: 'Email delivery failed. Check your Resend sender and domain configuration.'
        });
      }

      challenges.set(uid, {
        challengeId,
        email,
        codeHash: hash(code),
        createdAt,
        expiresAt,
        attempts: 0
      });

      return res.json({
        message: 'Verification code sent.',
        challengeId,
        expiresInSeconds: 300
      });
    } catch (error) {
      console.error('Email provider error:', error.message);

      return res.status(502).json({
        error: 'Unable to send verification email right now.'
      });
    }
  }
);

// --------------------------------------------------
// 10. Verify the email OTP
// --------------------------------------------------

app.post(
  '/api/auth/verify-otp',
  verifyLimiter,
  requireFirebaseUser,
  (req, res) => {
    const { code, challengeId } = req.body || {};

    if (
      typeof code !== 'string' ||
      !/^\d{6}$/.test(code) ||
      typeof challengeId !== 'string'
    ) {
      return res.status(400).json({
        error: 'Enter the six-digit code from your email.'
      });
    }

    const uid = req.firebaseUser.uid;
    const challenge = challenges.get(uid);

    if (
      !challenge ||
      challenge.challengeId !== challengeId
    ) {
      return res.status(400).json({
        error: 'Code not found. Request a new code.'
      });
    }

    if (Date.now() > challenge.expiresAt) {
      challenges.delete(uid);

      return res.status(400).json({
        error: 'Code expired. Request a new code.'
      });
    }

    challenge.attempts += 1;

    if (challenge.attempts > MAX_ATTEMPTS) {
      challenges.delete(uid);

      return res.status(429).json({
        error: 'Too many incorrect attempts. Request a new code.'
      });
    }

    if (!safeEqualHex(hash(code), challenge.codeHash)) {
      return res.status(400).json({
        error: 'Incorrect code. Please try again.'
      });
    }

    // OTP can be used only once.
    challenges.delete(uid);

    const sessionToken = signSession(uid, challenge.email);

    sessions.set(hash(sessionToken), {
      uid,
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    return res.json({
      message: 'MFA verified. Login successful.',
      sessionToken,
      expiresInSeconds: 3600
    });
  }
);

// --------------------------------------------------
// 11. Check application session
// --------------------------------------------------

app.get('/api/auth/session', (req, res) => {
  const token = bearer(req);
  const session = verifySessionToken(token);

  if (!session || !sessions.has(hash(token))) {
    return res.status(401).json({
      authenticated: false
    });
  }

  const storedSession = sessions.get(hash(token));

  if (storedSession.expiresAt <= Date.now()) {
    sessions.delete(hash(token));

    return res.status(401).json({
      authenticated: false
    });
  }

  return res.json({
    authenticated: true,
    uid: session.uid,
    email: session.email,
    expiresAt: session.exp
  });
});

// --------------------------------------------------
// 12. Logout
// --------------------------------------------------

app.post('/api/auth/logout', (req, res) => {
  const token = bearer(req);

  if (token) {
    sessions.delete(hash(token));
  }

  return res.json({
    message: 'Logged out.'
  });
});

// --------------------------------------------------
// 13. Handle unknown routes
// --------------------------------------------------

app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found.',
    path: req.path
  });
});

// --------------------------------------------------
// 14. Central error handler
// --------------------------------------------------

app.use((err, _req, res, _next) => {
  if (err.message === 'Origin not allowed by CORS') {
    return res.status(403).json({
      error: 'Origin not allowed by CORS.'
    });
  }

  console.error('Unhandled server error:', err.message);

  return res.status(500).json({
    error: 'Internal server error.'
  });
});

// --------------------------------------------------
// 15. Clean up expired challenges and sessions
// --------------------------------------------------

const cleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [uid, challenge] of challenges) {
    if (challenge.expiresAt <= now) {
      challenges.delete(uid);
    }
  }

  for (const [key, session] of sessions) {
    if (session.expiresAt <= now) {
      sessions.delete(key);
    }
  }
}, 60_000);

cleanupTimer.unref();

// --------------------------------------------------
// 16. Start server
// --------------------------------------------------

app.listen(PORT, () => {
  console.log(`MyProfile MFA API listening on port ${PORT}`);
});
