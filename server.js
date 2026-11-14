'use strict';
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { Readable } = require('stream');
const express = require('express');
const { Pool } = require('pg');

const scrypt = promisify(crypto.scrypt);

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
// Used only to create the very first admin (when the users table is empty) or when RESET_ADMIN=true.
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_DAYS = 7;
const MIN_PASSWORD = 8;
const ROLES = ['admin', 'contractor'];

if (!DATABASE_URL) { console.error('DATABASE_URL is not set'); process.exit(1); }

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Render's internal URL needs no SSL; set PGSSL=true when connecting via the external URL.
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined,
});

/* ------------------------------------------------------------------ passwords */

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(String(pw), salt, 64);
  return salt.toString('hex') + ':' + key.toString('hex');
}
async function verifyPassword(pw, stored) {
  const parts = String(stored || '').split(':');
  if (parts.length !== 2) return false;
  const key = await scrypt(String(pw), Buffer.from(parts[0], 'hex'), 64);
  const expected = Buffer.from(parts[1], 'hex');
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}
let DUMMY_HASH = null; // compared against when the email is unknown, so timing does not reveal valid emails

/* ------------------------------------------------------------------ helpers */

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
function normEmail(v) { return String(v || '').trim().toLowerCase(); }
function validEmail(e) { return e.length <= 254 && /^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$/.test(e); }
function getCookie(req, name) {
  const header = req.headers.cookie || '';
  const parts = header.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i], eq = p.indexOf('=');
    if (eq > 0 && p.slice(0, eq).trim() === name) {
      try { return decodeURIComponent(p.slice(eq + 1).trim()); } catch (e) { return null; }
    }
  }
  return null;
}

// Failed-login limiter: 10 failures per IP+email per 15 minutes.
const attempts = new Map();
function tooMany(key) {
  const a = attempts.get(key);
  if (!a) return false;
  if (Date.now() - a.first > 15 * 60 * 1000) { attempts.delete(key); return false; }
  return a.n >= 10;
}
function noteFail(key) {
  const a = attempts.get(key);
  if (!a || Date.now() - a.first > 15 * 60 * 1000) attempts.set(key, { n: 1, first: Date.now() });
  else a.n += 1;
}
setInterval(() => {
  const now = Date.now();
  attempts.forEach((a, k) => { if (now - a.first > 15 * 60 * 1000) attempts.delete(k); });
}, 10 * 60 * 1000).unref();

/* ------------------------------------------------------------------ Google Drive (optional) */

let drive = null;
let driveFolder = null;

function initDrive() {
  driveFolder = (process.env.GOOGLE_DRIVE_FOLDER_ID || '').trim();
  if (!driveFolder) { console.log('Google Drive: not configured (GOOGLE_DRIVE_FOLDER_ID missing). PDFs will not be stored.'); return; }
  try {
    const gd = require('@googleapis/drive');
    let authClient;
    if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
      authClient = new gd.auth.GoogleAuth({
        credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
        scopes: ['https://www.googleapis.com/auth/drive'],
      });
    } else if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN) {
      authClient = new gd.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
      authClient.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });
    } else {
      console.warn('Google Drive: folder set but no credentials (GOOGLE_SERVICE_ACCOUNT_JSON, or GOOGLE_CLIENT_ID/SECRET/REFRESH_TOKEN).');
      return;
    }
    drive = gd.drive({ version: 'v3', auth: authClient });
    console.log('Google Drive: ready');
  } catch (e) {
    console.error('Google Drive setup failed:', e.message);
    drive = null;
  }
}

function isNotFound(e) { return e && (e.code === 404 || (e.response && e.response.status === 404)); }

async function uploadToDrive(buf, name, existingId) {
  const media = () => ({ mimeType: 'application/pdf', body: Readable.from([buf]) });
  if (existingId) {
    try {
      const r = await drive.files.update({
        fileId: existingId, requestBody: { name }, media: media(),
        fields: 'id, webViewLink', supportsAllDrives: true,
      });
      return r.data;
    } catch (e) {
      if (!isNotFound(e)) throw e; // file was deleted in Drive: fall through and create a new one
    }
  }
  const r = await drive.files.create({
    requestBody: { name, parents: [driveFolder] }, media: media(),
    fields: 'id, webViewLink', supportsAllDrives: true,
  });
  return r.data;
}

/* ------------------------------------------------------------------ app + middleware */

const app = express();
app.set('trust proxy', 1); // Render terminates TLS in front of the app
app.disable('x-powered-by');

app.get('/healthz', (req, res) => res.send('ok')); // unauthenticated, for Render health checks

app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
  });
  next();
});

// Block cross-site writes (SameSite=Lax cookies already help; this is a second layer).
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.headers.origin) {
    let host = '';
    try { host = new URL(req.headers.origin).host; } catch (e) { /* ignore */ }
    if (host !== req.headers.host) return res.status(403).json({ error: 'Cross-site request blocked' });
  }
  next();
});

app.use(express.json({ limit: '5mb' }));

app.use(ah(async (req, res, next) => {
  req.user = null;
  const token = getCookie(req, 'sid');
  if (token) {
    const { rows } = await pool.query(
      `SELECT u.email, u.role, u.must_change
         FROM sessions s JOIN users u ON u.email = s.email
        WHERE s.id = $1 AND s.expires_at > now()`, [sha(token)]);
    if (rows[0]) req.user = { email: rows[0].email, role: rows[0].role, mustChange: rows[0].must_change, sid: sha(token) };
  }
  next();
}));

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not signed in' });
  if (req.user.mustChange) return res.status(403).json({ error: 'You need to set a new password first', mustChange: true });
  next();
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only admins can do this' });
    next();
  });
}

async function startSession(req, res, email) {
  const token = crypto.randomBytes(32).toString('base64url');
  const maxAge = SESSION_DAYS * 24 * 60 * 60 * 1000;
  await pool.query('INSERT INTO sessions (id, email, expires_at) VALUES ($1, $2, $3)',
    [sha(token), email, new Date(Date.now() + maxAge)]);
  res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', secure: req.secure, maxAge, path: '/' });
}

/* ------------------------------------------------------------------ pages */

const page = (f) => path.join(__dirname, 'public', f);
app.get('/login', (req, res) => {
  if (req.user && !req.user.mustChange && req.query.change !== '1') return res.redirect('/');
  res.sendFile(page('login.html'));
});
app.get('/', (req, res) => {
  if (!req.user || req.user.mustChange) return res.redirect('/login');
  res.sendFile(page('index.html'));
});
app.get('/admin', (req, res) => {
  if (!req.user || req.user.mustChange) return res.redirect('/login');
  if (req.user.role !== 'admin') return res.redirect('/');
  res.sendFile(page('admin.html'));
});

/* ------------------------------------------------------------------ auth API */

app.post('/api/login', ah(async (req, res) => {
  const email = normEmail(req.body && req.body.email);
  const password = String((req.body && req.body.password) || '');
  const key = req.ip + '|' + email;
  if (tooMany(key)) return res.status(429).json({ error: 'Too many failed attempts. Try again in a few minutes.' });
  const { rows } = await pool.query('SELECT email, role, password_hash, must_change FROM users WHERE email = $1', [email]);
  const u = rows[0];
  const ok = await verifyPassword(password, u ? u.password_hash : DUMMY_HASH);
  if (!u || !ok) { noteFail(key); return res.status(401).json({ error: 'Incorrect email or password' }); }
  attempts.delete(key);
  await pool.query('UPDATE users SET last_login_at = now() WHERE email = $1', [u.email]);
  await startSession(req, res, u.email);
  res.json({ email: u.email, role: u.role, mustChange: u.must_change });
}));

app.post('/api/logout', ah(async (req, res) => {
  const token = getCookie(req, 'sid');
  if (token) await pool.query('DELETE FROM sessions WHERE id = $1', [sha(token)]);
  res.clearCookie('sid', { path: '/' });
  res.json({ ok: true });
}));

app.get('/api/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not signed in' });
  res.json({
    email: req.user.email, role: req.user.role, mustChange: req.user.mustChange,
    drive: req.user.role === 'admin' ? !!drive : undefined,
  });
});

app.post('/api/change-password', ah(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not signed in' });
  const current = String((req.body && req.body.current) || '');
  const next = String((req.body && req.body.next) || '');
  if (next.length < MIN_PASSWORD) return res.status(400).json({ error: 'The new password needs at least ' + MIN_PASSWORD + ' characters' });
  if (next === current) return res.status(400).json({ error: 'Choose a password different from the current one' });
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE email = $1', [req.user.email]);
  if (!rows[0] || !(await verifyPassword(current, rows[0].password_hash))) {
    return res.status(400).json({ error: 'The current password is not correct' });
  }
  await pool.query('UPDATE users SET password_hash = $2, must_change = false WHERE email = $1', [req.user.email, await hashPassword(next)]);
  await pool.query('DELETE FROM sessions WHERE email = $1 AND id <> $2', [req.user.email, req.user.sid]);
  res.json({ ok: true });
}));

/* ------------------------------------------------------------------ user management (admins only) */

app.get('/api/users', requireAdmin, ah(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT email, role, must_change, created_at, last_login_at FROM users ORDER BY role, email');
  res.json(rows.map((r) => ({
    email: r.email, role: r.role, mustChange: r.must_change,
    createdAt: r.created_at, lastLoginAt: r.last_login_at, you: r.email === req.user.email,
  })));
}));

app.post('/api/users', requireAdmin, ah(async (req, res) => {
  const body = req.body || {};
  const role = String(body.role || '');
  const temp = String(body.tempPassword || '');
  const list = Array.isArray(body.emails) ? body.emails : String(body.emails || '').split(/[\s,;]+/);
  const emails = Array.from(new Set(list.map(normEmail).filter(Boolean)));
  if (ROLES.indexOf(role) < 0) return res.status(400).json({ error: 'Choose a role' });
  if (temp.length < MIN_PASSWORD) return res.status(400).json({ error: 'The temporary password needs at least ' + MIN_PASSWORD + ' characters' });
  if (!emails.length) return res.status(400).json({ error: 'Enter at least one email address' });
  if (emails.length > 200) return res.status(400).json({ error: 'Add at most 200 people at a time' });
  const out = { added: [], existing: [], invalid: [] };
  for (const email of emails) {
    if (!validEmail(email)) { out.invalid.push(email); continue; }
    const r = await pool.query(
      `INSERT INTO users (email, role, password_hash, must_change) VALUES ($1, $2, $3, true)
       ON CONFLICT (email) DO NOTHING`, [email, role, await hashPassword(temp)]);
    (r.rowCount ? out.added : out.existing).push(email);
  }
  res.json(out);
}));

app.patch('/api/users/:email', requireAdmin, ah(async (req, res) => {
  const email = normEmail(req.params.email);
  const body = req.body || {};
  const { rows } = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
  if (!rows[0]) return res.status(404).json({ error: 'No such user' });
  if (body.role !== undefined) {
    if (ROLES.indexOf(body.role) < 0) return res.status(400).json({ error: 'Choose a role' });
    if (email === req.user.email && body.role !== req.user.role) {
      return res.status(400).json({ error: 'You cannot change your own role. Ask another admin.' });
    }
    await pool.query('UPDATE users SET role = $2 WHERE email = $1', [email, body.role]);
  }
  if (body.tempPassword !== undefined) {
    const temp = String(body.tempPassword);
    if (email === req.user.email) return res.status(400).json({ error: 'Use "Change password" on the dashboard to change your own password.' });
    if (temp.length < MIN_PASSWORD) return res.status(400).json({ error: 'The temporary password needs at least ' + MIN_PASSWORD + ' characters' });
    await pool.query('UPDATE users SET password_hash = $2, must_change = true WHERE email = $1', [email, await hashPassword(temp)]);
    await pool.query('DELETE FROM sessions WHERE email = $1', [email]);
  }
  res.json({ ok: true });
}));

app.delete('/api/users/:email', requireAdmin, ah(async (req, res) => {
  const email = normEmail(req.params.email);
  if (email === req.user.email) return res.status(400).json({ error: 'You cannot remove your own account' });
  await pool.query('DELETE FROM users WHERE email = $1', [email]); // sessions go with it (ON DELETE CASCADE)
  res.json({ ok: true });
}));

/* ------------------------------------------------------------------ reports */

app.get('/api/reports', requireAuth, ah(async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const { rows } = await pool.query('SELECT id, data, drive_url FROM reports ORDER BY report_date, id');
  res.json(rows.map((r) => {
    const o = Object.assign({}, r.data, { id: r.id });
    if (isAdmin && r.drive_url) o.driveUrl = r.drive_url; else delete o.driveUrl;
    return o;
  }));
}));

app.put('/api/reports/:id', requireAdmin, ah(async (req, res) => {
  const body = req.body || {};
  if (!body.date || !/^\d{4}-\d{2}-\d{2}$/.test(body.date) || !Array.isArray(body.rows)) {
    return res.status(400).json({ error: 'A report needs a date (YYYY-MM-DD) and a rows array' });
  }
  const data = Object.assign({}, body);
  delete data.id; delete data.driveUrl;
  await pool.query(
    `INSERT INTO reports (id, report_date, data, updated_at)
     VALUES ($1, $2, $3, now())
     ON CONFLICT (id) DO UPDATE SET report_date = EXCLUDED.report_date, data = EXCLUDED.data, updated_at = now()`,
    [req.params.id, body.date, data]);
  res.json({ ok: true });
}));

app.delete('/api/reports/:id', requireAdmin, ah(async (req, res) => {
  // The PDF stays in Google Drive on purpose: it is the archive of what the client sent.
  await pool.query('DELETE FROM reports WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
}));

app.post('/api/reports/:id/pdf', requireAdmin, express.raw({ type: 'application/pdf', limit: '30mb' }), ah(async (req, res) => {
  if (!drive) return res.json({ ok: true, skipped: true });
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || buf.length < 5 || buf.slice(0, 4).toString('latin1') !== '%PDF') {
    return res.status(400).json({ error: 'That file is not a PDF' });
  }
  const { rows } = await pool.query('SELECT drive_file_id FROM reports WHERE id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Save the report before uploading its PDF' });
  let original = 'report.pdf';
  try { original = decodeURIComponent(String(req.headers['x-file-name'] || original)); } catch (e) { /* keep default */ }
  original = original.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').slice(0, 150) || 'report.pdf';
  let file;
  try {
    file = await uploadToDrive(buf, req.params.id + ' - ' + original, rows[0].drive_file_id);
  } catch (e) {
    console.error('Drive upload failed:', e.message);
    return res.status(502).json({ error: 'Google Drive refused the upload: ' + e.message });
  }
  await pool.query('UPDATE reports SET drive_file_id = $2, drive_url = $3 WHERE id = $1',
    [req.params.id, file.id, file.webViewLink || null]);
  res.json({ ok: true, driveUrl: file.webViewLink || null });
}));

app.post('/api/drive/test', requireAdmin, ah(async (req, res) => {
  if (!drive) return res.status(400).json({ error: 'Google Drive is not configured on the server yet.' });
  try {
    const r = await drive.files.get({ fileId: driveFolder, fields: 'id, name, mimeType', supportsAllDrives: true });
    if (r.data.mimeType !== 'application/vnd.google-apps.folder') {
      return res.status(400).json({ error: 'GOOGLE_DRIVE_FOLDER_ID points to a file, not a folder.' });
    }
    res.json({ ok: true, folder: r.data.name });
  } catch (e) {
    res.status(502).json({ error: 'Could not open the Drive folder: ' + e.message });
  }
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((req, res) => res.redirect('/'));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return;
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'The file is too large' });
  res.status(500).json({ error: 'Something went wrong on the server' });
});

/* ------------------------------------------------------------------ startup */

async function setup() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id          TEXT PRIMARY KEY,
      report_date DATE NOT NULL,
      data        JSONB NOT NULL,
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE reports ADD COLUMN IF NOT EXISTS drive_file_id TEXT;
    ALTER TABLE reports ADD COLUMN IF NOT EXISTS drive_url TEXT;
    CREATE TABLE IF NOT EXISTS users (
      email         TEXT PRIMARY KEY,
      role          TEXT NOT NULL CHECK (role IN ('admin', 'contractor')),
      password_hash TEXT NOT NULL,
      must_change   BOOLEAN NOT NULL DEFAULT false,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_login_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id         TEXT PRIMARY KEY,
      email      TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_email_idx ON sessions (email);
  `);
  DUMMY_HASH = await hashPassword(crypto.randomBytes(8).toString('hex'));

  const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
  const reset = process.env.RESET_ADMIN === 'true';
  if (rows[0].n === 0 || reset) {
    if (!ADMIN_EMAIL || !APP_PASSWORD) {
      if (rows[0].n === 0) throw new Error('No users yet: set ADMIN_EMAIL and APP_PASSWORD to create the first admin.');
    } else {
      await pool.query(
        `INSERT INTO users (email, role, password_hash, must_change) VALUES ($1, 'admin', $2, false)
         ON CONFLICT (email) DO UPDATE SET role = 'admin', password_hash = EXCLUDED.password_hash, must_change = false`,
        [ADMIN_EMAIL, await hashPassword(APP_PASSWORD)]);
      await pool.query('DELETE FROM sessions WHERE email = $1', [ADMIN_EMAIL]);
      console.log('Admin account ready for ' + ADMIN_EMAIL + (reset ? ' (RESET_ADMIN is on: remove it after signing in)' : ''));
    }
  }

  const clean = () => pool.query('DELETE FROM sessions WHERE expires_at < now()').catch((e) => console.error(e.message));
  await clean();
  setInterval(clean, 60 * 60 * 1000).unref();

  initDrive();
  app.listen(PORT, () => console.log('Listening on ' + PORT));
}

setup().catch((e) => { console.error('Startup failed:', e.message); process.exit(1); });
