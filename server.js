'use strict';
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const APP_USER = process.env.APP_USER || 'team';
const APP_PASSWORD = process.env.APP_PASSWORD;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) { console.error('DATABASE_URL is not set'); process.exit(1); }
if (!APP_PASSWORD) { console.error('APP_PASSWORD is not set'); process.exit(1); }

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Render's internal URL needs no SSL; set PGSSL=true when connecting via the external URL.
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined,
});

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function basicAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString();
    const i = decoded.indexOf(':');
    const user = decoded.slice(0, i);
    const pass = decoded.slice(i + 1);
    if (i >= 0 && safeEqual(user, APP_USER) && safeEqual(pass, APP_PASSWORD)) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Contractor Review Tracker"');
  res.status(401).send('Authentication required');
}

const app = express();
app.get('/healthz', (req, res) => res.send('ok')); // unauthenticated, for Render health checks
app.use(basicAuth);
app.use(express.json({ limit: '5mb' }));

app.get('/api/reports', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, data FROM reports ORDER BY report_date, id');
    res.json(rows.map((r) => Object.assign({}, r.data, { id: r.id })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not load reports' });
  }
});

app.put('/api/reports/:id', async (req, res) => {
  const body = req.body || {};
  if (!body.date || !/^\d{4}-\d{2}-\d{2}$/.test(body.date) || !Array.isArray(body.rows)) {
    return res.status(400).json({ error: 'A report needs a date (YYYY-MM-DD) and a rows array' });
  }
  const data = Object.assign({}, body);
  delete data.id;
  try {
    await pool.query(
      `INSERT INTO reports (id, report_date, data, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (id) DO UPDATE SET report_date = EXCLUDED.report_date, data = EXCLUDED.data, updated_at = now()`,
      [req.params.id, body.date, data]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not save report' });
  }
});

app.delete('/api/reports/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM reports WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not remove report' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

pool
  .query(`CREATE TABLE IF NOT EXISTS reports (
            id          TEXT PRIMARY KEY,
            report_date DATE NOT NULL,
            data        JSONB NOT NULL,
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
          )`)
  .then(() => app.listen(PORT, () => console.log('Listening on ' + PORT)))
  .catch((e) => { console.error('Database setup failed', e); process.exit(1); });
