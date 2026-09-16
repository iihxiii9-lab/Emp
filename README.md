# ركن (Rukn) — Employee Parking Management System

A single, fully self-contained HTML file. No server, no build step, no dependencies —
just `index.html`. This makes it deployable anywhere that can host static files,
**including GitHub Pages.**

## Deploy on GitHub Pages

1. Push `index.html` to a GitHub repository (at the repo root, or in whatever folder
   you point Pages at).
2. In the repo, go to **Settings → Pages**, set the source branch (e.g. `main`) and
   folder (`/root`), and save.
3. GitHub will publish it at `https://<your-username>.github.io/<repo-name>/`.

That's it — no server process to keep running, no `node` command needed. Any static host
works the same way (Netlify, Vercel, S3, your own web server, etc.) since the whole app is
one HTML file.

## How it works — everything runs in your browser

There is no backend. All data — accounts, vehicles, visitor permits, bookings, TOTP
secrets, and WebAuthn credentials — is stored in the browser's `localStorage`, scoped to
whichever device and browser you're using.

**What that means in practice:**
- Data is saved instantly (no network round-trip needed) every time you register a
  vehicle, add a visitor, or confirm a booking.
- Data does **not** sync across devices or browsers — an account created in Chrome on
  your laptop won't be visible in Safari or on your phone. It's local to that one browser.
- Clearing your browser's site data / cookies / cache for this page will erase everything.
- Click **"تنزيل نسخة JSON"** in the top bar any time to export the current data as a real
  `.json` file you can keep or share.

## تسجيل الدخول / إنشاء حساب (Sign in / Sign up)

No password field anywhere — accounts are created and logged into purely with a passkey
(your device's fingerprint / Face ID / Windows Hello), using the browser's real WebAuthn
API (`navigator.credentials.create` / `.get`).

- **إنشاء حساب (Sign up)** — enter a full name and username, click the button, and your OS
  prompts for your fingerprint/Face ID/Windows Hello. That registers a passkey tied to the
  new account (stored in `localStorage`) and logs you straight in.
- **تسجيل الدخول (Sign in)** — enter your username and click the button; same biometric
  prompt, checked against the credential stored for that account in this browser.
- Your session persists across page refreshes (until you click the logout icon) via
  `localStorage`, not a cookie — again, no server involved.

**WebAuthn requires a secure context** — either `https://` (which GitHub Pages provides
automatically) or `http://localhost` during local testing. It will not work if you open the
file directly from disk (`file:///...`) or over plain `http://` on a non-localhost address.

**Caveat:** login "verification" here just checks that the credential id the browser
returns matches the one stored for that username — there's no server to cryptographically
verify a signed assertion against, since there is no server. This is a genuine passkey
prompt gating genuine local access control, but it is not hardened the way a real backend
WebAuthn relying party would be.

## الأمان والمصادقة الثنائية (Security / 2FA)

A separate "الأمان والمصادقة الثنائية" tab, scoped per logged-in account:

- **TOTP** — generates a real RFC 6238 secret (Google Authenticator / Authy compatible,
  HMAC-SHA1, 6 digits, 30-second step) using the browser's Web Crypto API
  (`crypto.subtle`), shown for manual entry into your authenticator app. Verifying a
  6-digit code checks it with a ±1 time-step window for clock drift. This math was
  independently cross-checked against a reference Python implementation and matches
  exactly.
- **WebAuthn device registration** — a second, separate passkey you can register in
  addition to the one used for login (e.g. to simulate adding another trusted device).
  Also uses the real `navigator.credentials.create()` prompt.
- **Permanent delete** — removes the stored WebAuthn credential from this browser's
  `localStorage` for good, after a confirmation prompt.
- **Attempts log** — every setup/verify/register/delete/login/signup action is recorded
  with a timestamp and success/fail result, shown newest-first.

## Browser support

Needs a modern browser with WebAuthn platform-authenticator support: Chrome, Edge, Safari,
or Firefox, on a device with Touch ID, Face ID, Windows Hello, or a fingerprint reader set
up in the OS.
