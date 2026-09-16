/**
 * ركن (Rukn) — Employee Parking Management System
 * Tiny local server, no npm dependencies required.
 *
 * Run:   node server.js
 * Open:  http://localhost:3000
 *
 * Whenever the page registers a vehicle, issues a visitor permit, or
 * confirms a booking, it POSTs the full data set to /api/save, which
 * writes it straight into epms-data.json on this machine's disk —
 * no browser download involved.
 *
 * Also implements a small security section: TOTP (RFC 6238, Google
 * Authenticator compatible) and WebAuthn platform-authenticator (device
 * fingerprint / Face ID / Windows Hello) registration, with a permanent
 * delete for the stored credential and a log of recent attempts.
 *
 * Plus a passwordless accounts system: sign up creates an account and
 * registers a passkey in the same step; sign in authenticates purely with
 * that passkey (navigator.credentials.get()). Sessions are a random token
 * in an httpOnly cookie, kept in memory (not written to epms-data.json).
 *
 * NOTE on WebAuthn here: this is a minimal, educational flow. It stores the
 * credential id returned by the browser but does not parse the COSE public
 * key or verify attestation/assertion signatures — a real production system
 * would use a library (e.g. @simplewebauthn/server) to do full cryptographic
 * verification. It's enough to genuinely trigger your OS's real
 * fingerprint/Face ID/Windows Hello prompt and to track registration/login/
 * removal events, but should not be trusted as-is for a real login system.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'epms-data.json');
const HTML_FILE = path.join(__dirname, 'index.html');
const MAX_ATTEMPTS = 30;

function defaultData() {
  return {
    vehicles: [],
    visitors: [],
    bookings: [],
    users: [],
    security: {
      totp: { secret: null, otpauthUrl: null, enabled: false },
      webauthn: { credentialId: null, label: null, registeredAt: null },
      attempts: []
    }
  };
}

function readData() {
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    data.vehicles = data.vehicles || [];
    data.visitors = data.visitors || [];
    data.bookings = data.bookings || [];
    data.users = data.users || [];
    data.security = data.security || defaultData().security;
    data.security.totp = data.security.totp || { secret: null, otpauthUrl: null, enabled: false };
    data.security.webauthn = data.security.webauthn || { credentialId: null, label: null, registeredAt: null };
    data.security.attempts = data.security.attempts || [];
    return data;
  } catch (e) {
    return defaultData();
  }
}

function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function logAttempt(data, entry) {
  data.security.attempts.unshift({ ...entry, time: new Date().toISOString() });
  data.security.attempts = data.security.attempts.slice(0, MAX_ATTEMPTS);
}

/* ---------------- Base32 (RFC 4648) — needed for TOTP secrets ---------------- */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += B32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(str) {
  str = str.replace(/=+$/, '').toUpperCase();
  let bits = 0, value = 0;
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const idx = B32_ALPHABET.indexOf(str[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/* ---------------- TOTP (RFC 6238) over HMAC-SHA1, 6 digits, 30s step ---------------- */
function hotp(secretBuf, counter) {
  const counterBuf = Buffer.alloc(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) { counterBuf[i] = tmp % 256; tmp = Math.floor(tmp / 256); }
  const hmac = crypto.createHmac('sha1', secretBuf).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 |
    (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 1000000;
  return code.toString().padStart(6, '0');
}

function verifyTotp(secretBase32, token) {
  if (!token || !/^\d{6}$/.test(token)) return false;
  const secretBuf = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let drift = -1; drift <= 1; drift++) {
    if (hotp(secretBuf, counter + drift) === token) return true;
  }
  return false;
}

/* ---------------- base64url helpers (WebAuthn challenge/credential ids) ---------------- */
function toBase64Url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// In-memory only — a WebAuthn registration challenge is short-lived and
// doesn't need to survive a server restart.
let pendingWebauthnChallenge = null;

/* ---------------- Accounts / sessions ---------------- */
// Pending signup/login WebAuthn ceremonies, and live sessions, are kept in
// memory only (not written to epms-data.json) since they're short-lived.
const pendingSignups = new Map(); // username -> { displayName, challenge }
const pendingLogins = new Map();  // username -> { challenge }
const sessions = new Map();       // token -> username

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function currentUsername(req) {
  const cookies = parseCookies(req);
  const token = cookies['epms_session'];
  if (!token) return null;
  return sessions.get(token) || null;
}

function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `epms_session=${token}; Path=/; HttpOnly; SameSite=Lax`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `epms_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function collectBody(req, cb) {
  let chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    try {
      const text = Buffer.concat(chunks).toString('utf8');
      cb(null, text ? JSON.parse(text) : {});
    } catch (e) {
      cb(e);
    }
  });
}

const server = http.createServer((req, res) => {
  try {
    handleRequest(req, res);
  } catch (e) {
    console.error(`[${new Date().toLocaleTimeString()}] Unhandled error:`, e);
    try {
      sendJSON(res, 500, { ok: false, error: 'Internal server error' });
    } catch (e2) { /* response already sent — nothing more we can do */ }
  }
});

function handleRequest(req, res) {
  const url = req.url.split('?')[0];

  // ---- API: read the current data ----
  if (req.method === 'GET' && url === '/api/data') {
    return sendJSON(res, 200, readData());
  }

  // ---- API: overwrite the data file with what the page currently holds ----
  if (req.method === 'POST' && url === '/api/save') {
    return collectBody(req, (err, incoming) => {
      if (err) return sendJSON(res, 400, { ok: false, error: 'Invalid JSON' });
      const data = readData();
      // The page only manages vehicles/visitors/bookings; keep security state
      // (TOTP/WebAuthn/attempts) exactly as it is on the server, since it's
      // only ever changed through the dedicated security endpoints below.
      data.vehicles = incoming.vehicles || [];
      data.visitors = incoming.visitors || [];
      data.bookings = incoming.bookings || [];
      writeData(data);
      console.log(`[${new Date().toLocaleTimeString()}] epms-data.json updated — ` +
        `${data.vehicles.length} vehicles, ${data.visitors.length} visitors, ${data.bookings.length} bookings`);
      return sendJSON(res, 200, { ok: true });
    });
  }

  // ==================== Accounts / passkey sign-in ====================

  // ---- Who's currently logged in? ----
  if (req.method === 'GET' && url === '/api/auth/me') {
    const username = currentUsername(req);
    if (!username) return sendJSON(res, 200, { loggedIn: false });
    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) return sendJSON(res, 200, { loggedIn: false });
    return sendJSON(res, 200, { loggedIn: true, username: user.username, displayName: user.displayName });
  }

  // ---- Sign up, step 1: reserve the username, hand back WebAuthn create() options ----
  if (req.method === 'POST' && url === '/api/auth/signup_start') {
    return collectBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { ok: false, error: 'Invalid JSON' });
      const username = (body.username || '').trim().toLowerCase();
      const displayName = (body.displayName || '').trim();
      if (!username || !displayName) {
        return sendJSON(res, 400, { ok: false, error: 'الاسم واسم المستخدم مطلوبان' });
      }
      const data = readData();
      if (data.users.some(u => u.username === username)) {
        return sendJSON(res, 409, { ok: false, error: 'اسم المستخدم مستخدم بالفعل' });
      }
      const challenge = crypto.randomBytes(32);
      pendingSignups.set(username, { displayName, challenge });
      return sendJSON(res, 200, {
        challenge: toBase64Url(challenge),
        rpName: 'Rukn EPMS',
        rpId: 'localhost',
        userId: toBase64Url(Buffer.from(username)),
        userName: username,
        userDisplayName: displayName
      });
    });
  }

  // ---- Sign up, step 2: store the new passkey-backed account and log the user in ----
  if (req.method === 'POST' && url === '/api/auth/signup_finish') {
    return collectBody(req, (err, body) => {
      const data = readData();
      if (err) {
        logAttempt(data, { type: 'auth', action: 'signup', result: 'fail', detail: 'فشل إنشاء الحساب (طلب غير صالح)' });
        writeData(data);
        return sendJSON(res, 400, { ok: false, error: 'Invalid JSON' });
      }
      const username = (body.username || '').trim().toLowerCase();
      const pending = pendingSignups.get(username);
      if (!body.credentialId || !pending) {
        logAttempt(data, { type: 'auth', action: 'signup', result: 'fail', detail: `فشل إنشاء الحساب (${username || 'غير معروف'})` });
        writeData(data);
        return sendJSON(res, 400, { ok: false, error: 'Signup session invalid or expired' });
      }
      const user = {
        username,
        displayName: pending.displayName,
        credentialId: body.credentialId,
        label: body.label || 'هذا الجهاز',
        createdAt: new Date().toISOString()
      };
      data.users.push(user);
      logAttempt(data, { type: 'auth', action: 'signup', result: 'success', detail: `تم إنشاء حساب جديد: ${username}` });
      writeData(data);
      pendingSignups.delete(username);

      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, username);
      setSessionCookie(res, token);
      console.log(`[${new Date().toLocaleTimeString()}] New account created: ${username}`);
      return sendJSON(res, 200, { ok: true, username: user.username, displayName: user.displayName });
    });
  }

  // ---- Sign in, step 1: look up the account, hand back WebAuthn get() options ----
  if (req.method === 'POST' && url === '/api/auth/login_start') {
    return collectBody(req, (err, body) => {
      if (err) return sendJSON(res, 400, { ok: false, error: 'Invalid JSON' });
      const username = (body.username || '').trim().toLowerCase();
      const data = readData();
      const user = data.users.find(u => u.username === username);
      if (!user) {
        return sendJSON(res, 404, { ok: false, error: 'لا يوجد حساب بهذا الاسم' });
      }
      const challenge = crypto.randomBytes(32);
      pendingLogins.set(username, { challenge });
      return sendJSON(res, 200, {
        challenge: toBase64Url(challenge),
        rpId: 'localhost',
        allowCredentialId: user.credentialId
      });
    });
  }

  // ---- Sign in, step 2: confirm the passkey assertion came back and start a session ----
  if (req.method === 'POST' && url === '/api/auth/login_finish') {
    return collectBody(req, (err, body) => {
      const data = readData();
      if (err) {
        logAttempt(data, { type: 'auth', action: 'login', result: 'fail', detail: 'محاولة دخول فاشلة (طلب غير صالح)' });
        writeData(data);
        return sendJSON(res, 400, { ok: false, error: 'Invalid JSON' });
      }
      const username = (body.username || '').trim().toLowerCase();
      const pending = pendingLogins.get(username);
      const user = data.users.find(u => u.username === username);

      if (!user || !pending || !body.credentialId || body.credentialId !== user.credentialId) {
        logAttempt(data, { type: 'auth', action: 'login', result: 'fail', detail: `محاولة دخول فاشلة (${username || 'غير معروف'})` });
        writeData(data);
        return sendJSON(res, 401, { ok: false, error: 'تعذّر التحقق من بصمة الجهاز' });
      }

      logAttempt(data, { type: 'auth', action: 'login', result: 'success', detail: `تسجيل دخول: ${username}` });
      writeData(data);
      pendingLogins.delete(username);

      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, username);
      setSessionCookie(res, token);
      console.log(`[${new Date().toLocaleTimeString()}] ${username} logged in`);
      return sendJSON(res, 200, { ok: true, username: user.username, displayName: user.displayName });
    });
  }

  // ---- Log out ----
  if (req.method === 'POST' && url === '/api/auth/logout') {
    const cookies = parseCookies(req);
    const token = cookies['epms_session'];
    if (token) sessions.delete(token);
    clearSessionCookie(res);
    return sendJSON(res, 200, { ok: true });
  }

  // ---- API: current security state (TOTP status, WebAuthn status, recent attempts) ----
  if (req.method === 'GET' && url === '/api/security') {
    const data = readData();
    const totp = data.security.totp;
    return sendJSON(res, 200, {
      totp: {
        enabled: totp.enabled,
        // Only expose the secret/otpauth URL while enrollment isn't finished yet
        secret: totp.enabled ? null : totp.secret,
        otpauthUrl: totp.enabled ? null : totp.otpauthUrl
      },
      webauthn: data.security.webauthn,
      attempts: data.security.attempts
    });
  }

  // ---- API: totp_setup — generate a fresh TOTP secret for enrollment ----
  if (req.method === 'POST' && url === '/api/totp_setup') {
    const data = readData();
    const secretBuf = crypto.randomBytes(20);
    const secret = base32Encode(secretBuf);
    const label = encodeURIComponent('Rukn EPMS:rashed.almansoori');
    const issuer = encodeURIComponent('Rukn EPMS');
    const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    data.security.totp = { secret, otpauthUrl, enabled: false };
    logAttempt(data, { type: 'totp', action: 'setup', result: 'success', detail: 'تم إنشاء رمز سرّي جديد' });
    writeData(data);
    console.log(`[${new Date().toLocaleTimeString()}] TOTP setup started`);
    return sendJSON(res, 200, { secret, otpauthUrl });
  }

  // ---- API: totp_verify — check a 6-digit code against the stored secret ----
  if (req.method === 'POST' && url === '/api/totp_verify') {
    return collectBody(req, (err, body) => {
      const data = readData();
      if (err || !data.security.totp.secret) {
        logAttempt(data, { type: 'totp', action: 'verify', result: 'fail', detail: 'لا يوجد إعداد TOTP نشط' });
        writeData(data);
        return sendJSON(res, 400, { ok: false, error: 'TOTP not set up' });
      }
      const valid = verifyTotp(data.security.totp.secret, (body.code || '').trim());
      if (valid) data.security.totp.enabled = true;
      logAttempt(data, {
        type: 'totp', action: 'verify',
        result: valid ? 'success' : 'fail',
        detail: valid ? 'تم التحقق من الرمز بنجاح' : 'رمز غير صحيح أو منتهي'
      });
      writeData(data);
      console.log(`[${new Date().toLocaleTimeString()}] TOTP verify — ${valid ? 'success' : 'failed'}`);
      return sendJSON(res, 200, { ok: valid, enabled: data.security.totp.enabled });
    });
  }

  // ---- API: webauthn_register_options — challenge + user info for navigator.credentials.create() ----
  if (req.method === 'POST' && url === '/api/webauthn_register_options') {
    pendingWebauthnChallenge = crypto.randomBytes(32);
    const userId = Buffer.from('rashed.almansoori');
    return sendJSON(res, 200, {
      challenge: toBase64Url(pendingWebauthnChallenge),
      rpName: 'Rukn EPMS',
      rpId: 'localhost',
      userId: toBase64Url(userId),
      userName: 'rashed.almansoori',
      userDisplayName: 'راشد المنصوري'
    });
  }

  // ---- API: webauthn_register — store the credential descriptor returned by the browser ----
  if (req.method === 'POST' && url === '/api/webauthn_register') {
    return collectBody(req, (err, body) => {
      const data = readData();
      if (err || !body.id) {
        logAttempt(data, { type: 'webauthn', action: 'register', result: 'fail', detail: 'استجابة غير صالحة من المتصفح' });
        writeData(data);
        return sendJSON(res, 400, { ok: false, error: 'Invalid credential' });
      }
      data.security.webauthn = {
        credentialId: body.id,
        label: body.label || 'هذا الجهاز',
        registeredAt: new Date().toISOString()
      };
      logAttempt(data, { type: 'webauthn', action: 'register', result: 'success', detail: 'تم تسجيل بصمة الجهاز' });
      writeData(data);
      pendingWebauthnChallenge = null;
      console.log(`[${new Date().toLocaleTimeString()}] WebAuthn credential registered`);
      return sendJSON(res, 200, { ok: true, webauthn: data.security.webauthn });
    });
  }

  // ---- API: webauthn_delete — permanently remove the stored credential descriptor ----
  if (req.method === 'DELETE' && url === '/api/webauthn_delete') {
    const data = readData();
    const hadOne = !!data.security.webauthn.credentialId;
    data.security.webauthn = { credentialId: null, label: null, registeredAt: null };
    logAttempt(data, {
      type: 'webauthn', action: 'delete',
      result: hadOne ? 'success' : 'fail',
      detail: hadOne ? 'تم حذف الواصف نهائيًا' : 'لا يوجد واصف مسجّل لحذفه'
    });
    writeData(data);
    console.log(`[${new Date().toLocaleTimeString()}] WebAuthn credential deleted`);
    return sendJSON(res, 200, { ok: true });
  }

  // ---- Serve the raw JSON file directly too, e.g. http://localhost:3000/epms-data.json ----
  if (req.method === 'GET' && url === '/epms-data.json') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(fs.readFileSync(DATA_FILE, 'utf8'));
  }

  // ---- Serve the app itself ----
  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(HTML_FILE, 'utf8'));
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
}

server.listen(PORT, () => {
  console.log(`ركن (Rukn) EPMS running at http://localhost:${PORT}`);
  console.log(`Saving data to: ${DATA_FILE}`);
});

// Last-resort safety net: log any truly unexpected error instead of letting
// it crash the whole server process.
process.on('uncaughtException', (e) => {
  console.error(`[${new Date().toLocaleTimeString()}] Uncaught exception (server kept running):`, e);
});
process.on('unhandledRejection', (e) => {
  console.error(`[${new Date().toLocaleTimeString()}] Unhandled promise rejection (server kept running):`, e);
});
