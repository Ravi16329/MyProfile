# MyProfile Firebase + Resend email MFA integration

This archive contains your existing portfolio plus an updated email/password + six-digit email OTP login page.

## Before testing
1. In `login.html`, replace `PASTE_FIREBASE_API_KEY`, `PASTE_FIREBASE_MESSAGING_SENDER_ID`, and `PASTE_FIREBASE_APP_ID` with the values from Firebase Console → Project settings → General → Your apps → SDK setup and configuration. The Firebase web config is intended for the browser; never put the Admin service-account private key here.
2. Confirm Render has `FRONTEND_URL=https://ravi16329.github.io` (origin only, no `/MyProfile` path), `RESEND_API_KEY`, `EMAIL_FROM`, `FIREBASE_SERVICE_ACCOUNT_JSON`, `SESSION_SECRET`, and `NODE_ENV=production`.
3. In Firebase Authentication, enable Email/Password. Users must verify their email before the backend will send an OTP.
4. Ensure the Resend sender is allowed to deliver to the recipient. `onboarding@resend.dev` is generally limited to testing with your own verified Resend account email.
5. Commit and push the updated `login.html` and `index.html` to GitHub.

## Important security limitation
The frontend stores the post-MFA token in `sessionStorage` and checks it against the backend before showing `index.html`. This is a navigation/UX gate only. GitHub Pages serves static files publicly, so it cannot make the HTML source private. Protect sensitive data/actions on the backend and verify the MFA session server-side. The current backend keeps OTP challenges and session allowlisting in memory; a Render restart clears them.
