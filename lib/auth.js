/**
 * Authentication: scrypt password hashing, DB-backed sessions,
 * cookie handling, and Express middleware. No external dependencies.
 */

const crypto = require('crypto');
const db = require('./db');

const SESSION_COOKIE = 'ls_session';
const SESSION_DAYS = 30;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

/* ---------------- passwords ---------------- */

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64, SCRYPT_PARAMS);
  return `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const [scheme, saltHex, hashHex] = stored.split(':');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, salt, expected.length, SCRYPT_PARAMS);
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/* ---------------- sessions ---------------- */

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare(
    `INSERT INTO sessions (token_hash, user_id, expires_at)
     VALUES (?, ?, datetime('now', '+${SESSION_DAYS} days'))`
  ).run(sha256(token), userId);
  return token;
}

function destroySession(token) {
  if (!token) return;
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
}

function userForSession(token) {
  if (!token) return null;
  return db.prepare(
    `SELECT u.id, u.email, u.created_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > datetime('now')`
  ).get(sha256(token)) || null;
}

/* ---------------- cookies ---------------- */

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie',
    `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

/* ---------------- middleware ---------------- */

/** Attaches req.user (or null) — never blocks. */
function attachUser(req, _res, next) {
  req.sessionToken = parseCookies(req)[SESSION_COOKIE] || null;
  req.user = userForSession(req.sessionToken);
  next();
}

/** Rejects with 401 when not signed in. */
function requireUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please sign in to use this feature.' });
  next();
}

/* ---------------- account operations ---------------- */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function signup(email, password) {
  email = String(email || '').trim().toLowerCase();
  password = String(password || '');
  if (!EMAIL_RE.test(email)) throw new Error('Please enter a valid email address.');
  if (password.length < 8) throw new Error('Password must be at least 8 characters.');
  if (password.length > 200) throw new Error('Password is too long.');

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) throw new Error('An account with that email already exists. Try signing in.');

  const info = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
    .run(email, hashPassword(password));
  return { id: info.lastInsertRowid, email };
}

function login(email, password) {
  email = String(email || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  // Always burn comparable time to avoid leaking which emails exist.
  const ok = user ? verifyPassword(password, user.password_hash)
                  : (hashPassword(String(password || '')), false);
  if (!ok) throw new Error('Incorrect email or password.');
  return { id: user.id, email: user.email };
}

module.exports = {
  hashPassword, verifyPassword,
  createSession, destroySession, userForSession,
  setSessionCookie, clearSessionCookie, parseCookies,
  attachUser, requireUser,
  signup, login,
  SESSION_COOKIE,
};
