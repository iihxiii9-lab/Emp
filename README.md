# ركن (Rukn) — Employee Parking Management System

## Run it

You need [Node.js](https://nodejs.org) installed — nothing else, no `npm install` required.

1. Put `server.js`, `index.html`, and `epms-data.json` in the same folder.
2. Open a terminal in that folder and run:
   ```
   node server.js
   ```
3. Open **http://localhost:3000** in your browser.

## How saving works

Every time you register a vehicle, issue a visitor permit, or confirm a booking in the app,
the page sends the full data set to `POST /api/save`, and the server writes it straight into
`epms-data.json` on your disk — instantly, with no browser download or file picker involved.

You can also watch it happen live:
- The terminal running `node server.js` logs a line every time the file is updated.
- Click **"عرض JSON عبر API"** in the top bar to open `/api/data` in a new tab and see the
  current saved data straight from the server.
- Open `epms-data.json` in a text editor to watch the file change in real time.

Other endpoints:
- `GET /api/data` — returns the current contents of `epms-data.json`
- `GET /epms-data.json` — same thing, served as a raw file

## Note

The app requires `node server.js` to be running — it saves and loads data purely through the
API, with no browser-storage or download fallback. If the server isn't reachable, saves will
fail with a toast telling you to start it.

## تسجيل الدخول / إنشاء حساب (Sign in / Sign up)

The app now opens on a sign-in screen — there's no password field anywhere; accounts are
created and logged into purely with a passkey (your device's fingerprint / Face ID / Windows
Hello), using the browser's real WebAuthn API.

- **إنشاء حساب (Sign up)** — enter a full name and username, click the button, and your OS
  will prompt for your fingerprint/Face ID/Windows Hello. That registers a passkey tied to the
  new account and logs you straight in.
- **تسجيل الدخول (Sign in)** — enter your username and click the button; you'll get the same
  biometric prompt, and on success you're taken into the app.
- Sessions are a random token in an httpOnly cookie, so refreshing the page keeps you signed
  in until you click the logout icon next to your name.
- Every signup/login attempt (success or failure) also shows up in the "سجلّ آخر المحاولات"
  log on the Security tab, alongside the TOTP/WebAuthn-device events.

**Caveat:** as with the WebAuthn device-registration feature, login verification here is
simplified — it checks that the credential id returned by the browser matches the one stored
for that username, but doesn't cryptographically verify the signed assertion. A real product
would use a library that does full WebAuthn verification before trusting a login.

## الأمان والمصادقة الثنائية (Security / 2FA)

A new "الأمان والمصادقة الثنائية" tab adds:

- **TOTP** — `totp_setup` (`POST /api/totp_setup`) generates a fresh RFC 6238 secret
  (Google Authenticator / Authy compatible, HMAC-SHA1, 6 digits, 30s step) and shows it for
  manual entry into your authenticator app. `totp_verify` (`POST /api/totp_verify`) checks a
  6-digit code against it (±1 time-step window for clock drift) and marks it enabled on success.
- **WebAuthn device registration** — the "تسجيل بصمة الجهاز" button calls the browser's real
  `navigator.credentials.create()` API, so it triggers your OS's actual Touch ID / Face ID /
  Windows Hello prompt. The returned credential id is stored server-side.
- **Permanent delete** — "حذف الواصف نهائيًا" removes the stored WebAuthn credential from
  `epms-data.json` for good (`DELETE /api/webauthn_delete`), after a confirmation prompt.
- **Attempts log** — every setup/verify/register/delete action is recorded with a timestamp
  and success/fail result, shown newest-first in the "سجلّ آخر المحاولات" card.

**Important caveat:** the WebAuthn implementation here is intentionally minimal for a local
demo — it stores the credential id but does not parse the COSE public key or cryptographically
verify attestation/assertion signatures. It's genuinely triggering and tracking real
platform-authenticator prompts, but a production system should use a vetted library (e.g.
`@simplewebauthn/server`) to do full verification before trusting a credential for login.
