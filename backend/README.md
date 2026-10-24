# MyProfile: Firebase Authentication + Resend Email OTP backend

This backend implements the second factor for the flow:

1. Frontend signs in with Firebase Email/Password.
2. Frontend sends the Firebase ID token to `POST /api/auth/request-otp`.
3. Backend verifies the token using Firebase Admin SDK and sends a six-digit OTP using Resend.
4. Frontend sends the Firebase ID token plus `challengeId` and OTP to `POST /api/auth/verify-otp`.
5. Backend returns a short-lived `sessionToken` only after the OTP is verified.

No PostgreSQL database is used.

## Important limitations

- OTP challenges and the session allowlist are held in memory. They disappear on Render restarts/deploys and are not shared across multiple instances. This is suitable for initial testing on one instance, not a robust multi-instance production setup. Use Redis or a database before scaling.
- Firebase client sign-in creates a Firebase session before email OTP verification. Your app must not treat the Firebase session alone as permission to access MFA-protected features. Gate protected backend routes using the post-MFA session token. Static GitHub Pages files are public; this cannot make static HTML itself secret.
- The backend requires the Firebase account email to be verified. Configure Firebase email verification and ask users to verify their email before login.
- Resend's `onboarding@resend.dev` sender is for testing and typically only permits delivery to your own verified account. For arbitrary recipients, verify a domain in Resend and set `EMAIL_FROM` to that domain.
- This backend does not create Firebase users. User registration can be handled by Firebase client SDK in the frontend.

## 1. Firebase Admin service account

In Firebase Console, select the `myprofile-auth` project. Open Project settings (gear) → Service accounts → Generate new private key. Download the JSON securely. Do not commit it to GitHub or upload it into the frontend. In Render, set `FIREBASE_SERVICE_ACCOUNT_JSON` to the entire JSON on one line. If the platform accepts multiline values, paste the JSON as-is; otherwise minify it to one line without changing values.

The service-account `project_id` must be `myprofile-auth` (or match the project used by your frontend).

## 2. Local setup

1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Set `FRONTEND_URL`, `RESEND_API_KEY`, `EMAIL_FROM`, `SESSION_SECRET`, and `FIREBASE_SERVICE_ACCOUNT_JSON`.
4. Run:

```bash
npm install
npm start
```

Health check: `http://localhost:3000/health`

## 3. Render deployment

Create a new GitHub repository for the backend and upload the contents of this folder at the repository root. Do not upload `.env` or service-account JSON files.

Create a Render **Web Service** connected to that repository:

- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`

Set these environment variables in Render:

- `NODE_ENV=production`
- `FRONTEND_URL=https://YOUR_GITHUB_USERNAME.github.io` (or your exact local origin while testing)
- `RESEND_API_KEY=re_...`
- `EMAIL_FROM=MyProfile Security <your-verified-sender@yourdomain.com>`
- `FIREBASE_SERVICE_ACCOUNT_JSON=<service account JSON>`
- `SESSION_SECRET=<long random secret, at least 32 characters>`

Render provides `PORT` automatically. Do not set `DATABASE_URL`.

## 4. Frontend API calls

Firebase client sign-in example (frontend, using Firebase Web SDK):

```js
import { getAuth, signInWithEmailAndPassword } from 'firebase/auth';
const auth = getAuth();
const credential = await signInWithEmailAndPassword(auth, email, password);
const idToken = await credential.user.getIdToken();
```

Request OTP:

```js
const start = await fetch(`${API_BASE}/api/auth/request-otp`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` }
});
const { challengeId } = await start.json();
```

Verify OTP:

```js
const result = await fetch(`${API_BASE}/api/auth/verify-otp`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
  body: JSON.stringify({ challengeId, code: otpFromInput })
});
const data = await result.json();
if (!result.ok) throw new Error(data.error || 'OTP verification failed');
// Keep sessionToken in memory where possible; do not treat Firebase ID token alone as MFA completion.
const sessionToken = data.sessionToken;
```

Check backend session by sending `Authorization: Bearer ${sessionToken}` to `/api/auth/session`.

The exact frontend integration depends on the existing login page and should be wired in without exposing `RESEND_API_KEY` in browser code.
