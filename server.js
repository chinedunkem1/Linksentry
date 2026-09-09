const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

/* Load .env if present — real env vars always win. */
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !m[1].startsWith('#') && !(m[1] in process.env)) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
} catch { /* no .env file — fine */ }

const db = require('./lib/db');
const { scanUrl } = require('./lib/scanner');
const auth = require('./lib/auth');
const apikeys = require('./lib/apikeys');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '64kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(auth.attachUser);
app.use(express.static(path.join(__dirname, 'public')));

/* ---------------- rate limiting (in-memory, per IP) ---------------- */

function makeLimiter(max, windowMs, message) {
  const buckets = new Map();
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const recent = (buckets.get(ip) || []).filter((t) => now - t < windowMs);
    if (recent.length >= max) return res.status(429).json({ error: message });
    recent.push(now);
    buckets.set(ip, recent);
    if (buckets.size > 10000) buckets.clear();
    next();
  };
}

const scanLimiter = makeLimiter(20, 60000, 'Rate limit reached — please wait a moment before scanning again.');
const authLimiter = makeLimiter(10, 60000, 'Too many attempts — please wait a minute and try again.');

/* ---------------- scan persistence ---------------- */

function saveScan(result, userId, source) {
  const publicId = crypto.randomBytes(6).toString('base64url');
  db.prepare(
    `INSERT INTO scans (public_id, user_id, url, verdict, score, result, source)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(publicId, userId || null, result.url, result.verdict, result.score,
        JSON.stringify(result), source);
  result.reportId = publicId;
  return result;
}

/* ================= scanning ================= */

app.post('/api/scan', scanLimiter, async (req, res) => {
  try {
    const result = await scanUrl((req.body || {}).url);
    saveScan(result, req.user?.id, 'web');
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Scan failed. Please try again.' });
  }
});

/* Fair-use batch size — keeps one request from monopolising the scanner. */
const BULK_LIMIT = 25;

app.post('/api/bulk-scan', auth.requireUser, async (req, res) => {
  const urls = [...new Set((Array.isArray(req.body?.urls) ? req.body.urls : [])
    .map((u) => String(u).trim()).filter(Boolean))];

  if (urls.length === 0) return res.status(400).json({ error: 'Provide at least one URL.' });
  if (urls.length > BULK_LIMIT) {
    return res.status(400).json({
      error: `Please scan at most ${BULK_LIMIT} URLs per batch (you submitted ${urls.length}). Split the list and run it again — there's no limit on how many batches you can do.`,
    });
  }

  const results = new Array(urls.length);
  let cursor = 0;
  async function worker() {
    while (cursor < urls.length) {
      const i = cursor++;
      try {
        const r = await scanUrl(urls[i]);
        saveScan(r, req.user.id, 'bulk');
        results[i] = { url: urls[i], ok: true, verdict: r.verdict, score: r.score, finalUrl: r.finalUrl, reportId: r.reportId };
      } catch (err) {
        results[i] = { url: urls[i], ok: false, error: err.message };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(5, urls.length) }, worker));
  res.json({ count: results.length, results });
});

/* ================= auth ================= */

app.post('/api/auth/signup', authLimiter, (req, res) => {
  try {
    const user = auth.signup(req.body?.email, req.body?.password);
    auth.setSessionCookie(res, auth.createSession(user.id));
    res.json({ email: user.email });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  try {
    const user = auth.login(req.body?.email, req.body?.password);
    auth.setSessionCookie(res, auth.createSession(user.id));
    res.json({ email: user.email });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  auth.destroySession(req.sessionToken);
  auth.clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.user) return res.json({ user: null });
  res.json({
    user: {
      email: req.user.email,
      createdAt: req.user.created_at,
      apiUsage: apikeys.usageForUser(req.user.id),
      bulkLimit: BULK_LIMIT,
      isAdmin: isAdmin(req.user.email),
    },
  });
});

/* ================= scan history ================= */

app.get('/api/history', auth.requireUser, (req, res) => {
  const rows = db.prepare(
    `SELECT public_id AS reportId, url, verdict, score, source, created_at AS createdAt
       FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 100`
  ).all(req.user.id);
  res.json({ scans: rows });
});

app.delete('/api/history', auth.requireUser, (req, res) => {
  db.prepare('DELETE FROM scans WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

/* ================= API keys ================= */

app.post('/api/keys', auth.requireUser, (req, res) => {
  try {
    const created = apikeys.createKey(req.user.id, req.body?.label);
    res.json(created); // full key shown exactly once
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/keys', auth.requireUser, (req, res) => {
  res.json({ keys: apikeys.listKeys(req.user.id) });
});

app.delete('/api/keys/:id', auth.requireUser, (req, res) => {
  try {
    apikeys.revokeKey(req.user.id, Number(req.params.id));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* ================= developer API v1 ================= */

app.post('/api/v1/scan', async (req, res) => {
  let keyAuth;
  try {
    keyAuth = apikeys.authenticateKey(req.headers['x-api-key']);
  } catch (err) {
    return res.status(err.status || 401).json({ error: err.message });
  }
  res.setHeader('X-Quota-Limit', keyAuth.quota);
  res.setHeader('X-Quota-Used', keyAuth.used);
  try {
    const result = await scanUrl((req.body || {}).url);
    saveScan(result, keyAuth.user.id, 'api');
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/v1/usage', (req, res) => {
  const rawKey = req.headers['x-api-key'];
  if (!rawKey || !rawKey.startsWith('lak_')) {
    return res.status(401).json({ error: 'Missing or malformed API key. Pass it in the X-Api-Key header.' });
  }
  const row = db.prepare(
    `SELECT u.id AS userId FROM api_keys k JOIN users u ON u.id = k.user_id
      WHERE k.key_hash = ? AND k.revoked_at IS NULL`
  ).get(crypto.createHash('sha256').update(rawKey).digest('hex'));
  if (!row) return res.status(401).json({ error: 'Invalid API key.' });
  res.json(apikeys.usageForUser(row.userId));
});

/* ================= shareable reports ================= */

app.get('/api/report/:publicId', (req, res) => {
  const row = db.prepare('SELECT result, created_at FROM scans WHERE public_id = ?')
    .get(req.params.publicId);
  if (!row) return res.status(404).json({ error: 'Report not found.' });
  const result = JSON.parse(row.result);
  result.reportId = req.params.publicId;
  res.json(result);
});

app.get('/r/:publicId', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

/* ================= admin (site owner) ================= */

function isAdmin(email) {
  return (process.env.ADMIN_EMAILS || '')
    .split(',').map((e) => e.trim().toLowerCase()).filter(Boolean)
    .includes((email || '').toLowerCase());
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please sign in.' });
  if (!isAdmin(req.user.email)) return res.status(403).json({ error: 'Admin access only.' });
  next();
}

app.get('/api/admin/overview', requireAdmin, (_req, res) => {
  const totals = {
    users: db.prepare('SELECT COUNT(*) AS n FROM users').get().n,
    scans: db.prepare('SELECT COUNT(*) AS n FROM scans').get().n,
    scansToday: db.prepare(`SELECT COUNT(*) AS n FROM scans WHERE created_at >= date('now')`).get().n,
    apiKeys: db.prepare('SELECT COUNT(*) AS n FROM api_keys WHERE revoked_at IS NULL').get().n,
    apiScans: db.prepare(`SELECT COUNT(*) AS n FROM scans WHERE source = 'api'`).get().n,
  };
  const users = db.prepare(
    `SELECT u.id, u.email, u.created_at AS createdAt,
            COUNT(s.id) AS scanCount,
            MAX(s.created_at) AS lastScanAt,
            (SELECT COUNT(*) FROM api_keys k WHERE k.user_id = u.id AND k.revoked_at IS NULL) AS activeKeys
       FROM users u LEFT JOIN scans s ON s.user_id = u.id
      GROUP BY u.id ORDER BY u.id DESC LIMIT 500`
  ).all();
  const recentScans = db.prepare(
    `SELECT s.url, s.verdict, s.score, s.source, s.created_at AS createdAt, u.email
       FROM scans s LEFT JOIN users u ON u.id = s.user_id
      ORDER BY s.id DESC LIMIT 25`
  ).all();
  res.json({ totals, users, recentScans });
});

app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

/* ================= misc ================= */

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'Linkaware', version: '2.0.0' });
});

app.get('/dashboard', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/login', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/docs', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'docs.html')));
app.get('/privacy', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found.' });
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.listen(PORT, () => {
  console.log(`Linkaware running at http://localhost:${PORT}`);
  console.log(`Google Safe Browsing: ${process.env.GSB_API_KEY ? 'ENABLED — blocklist checks active' : 'not configured (set GSB_API_KEY to enable)'}`);
});
