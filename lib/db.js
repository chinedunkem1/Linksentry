/**
 * SQLite persistence layer.
 * Database file lives in ./data (gitignored); override with DATA_DIR env.
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dataDir = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'linkaware.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash   TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  label      TEXT NOT NULL DEFAULT 'default',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS api_usage (
  key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  month  TEXT NOT NULL,             -- e.g. '2026-07'
  count  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_id, month)
);

CREATE TABLE IF NOT EXISTS scans (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id  TEXT NOT NULL UNIQUE,  -- shareable report id
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  url        TEXT NOT NULL,
  verdict    TEXT NOT NULL,
  score      INTEGER NOT NULL,
  result     TEXT NOT NULL,         -- full JSON payload
  source     TEXT NOT NULL DEFAULT 'web',  -- web | api | bulk
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
`);

/* Periodic cleanup of expired sessions (every 6 hours). */
function purgeExpiredSessions() {
  db.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`).run();
}
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 6 * 3600 * 1000).unref();

module.exports = db;
