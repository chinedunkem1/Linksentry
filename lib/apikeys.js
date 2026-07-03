/**
 * API key management and monthly quota tracking.
 * Keys look like: lsk_9f2c... (only a SHA-256 hash is stored).
 */

const crypto = require('crypto');
const db = require('./db');

const QUOTAS = { free: 100, pro: 10000 };
const MAX_KEYS_PER_USER = 5;

function sha256(v) {
  return crypto.createHash('sha256').update(v).digest('hex');
}

function currentMonth() {
  return new Date().toISOString().slice(0, 7); // '2026-07'
}

function createKey(userId, label) {
  const active = db.prepare(
    'SELECT COUNT(*) AS n FROM api_keys WHERE user_id = ? AND revoked_at IS NULL'
  ).get(userId).n;
  if (active >= MAX_KEYS_PER_USER) {
    throw new Error(`Key limit reached (${MAX_KEYS_PER_USER}). Revoke an unused key first.`);
  }
  const secret = 'lsk_' + crypto.randomBytes(24).toString('hex');
  const prefix = secret.slice(0, 12) + '…';
  const info = db.prepare(
    'INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?, ?, ?, ?)'
  ).run(userId, sha256(secret), prefix, String(label || 'default').slice(0, 60));
  return { id: info.lastInsertRowid, key: secret, prefix };
}

function listKeys(userId) {
  return db.prepare(
    `SELECT k.id, k.key_prefix AS prefix, k.label, k.created_at AS createdAt,
            k.revoked_at AS revokedAt,
            COALESCE(u.count, 0) AS usedThisMonth
       FROM api_keys k
       LEFT JOIN api_usage u ON u.key_id = k.id AND u.month = ?
      WHERE k.user_id = ?
      ORDER BY k.id DESC`
  ).all(currentMonth(), userId);
}

function revokeKey(userId, keyId) {
  const info = db.prepare(
    `UPDATE api_keys SET revoked_at = datetime('now')
      WHERE id = ? AND user_id = ? AND revoked_at IS NULL`
  ).run(keyId, userId);
  if (info.changes === 0) throw new Error('Key not found or already revoked.');
}

/**
 * Validates a raw API key and enforces the monthly quota.
 * Returns { keyId, user, quota, used } or throws with .status set.
 */
function authenticateKey(rawKey) {
  const fail = (status, message) => {
    const err = new Error(message);
    err.status = status;
    throw err;
  };
  if (!rawKey || !rawKey.startsWith('lsk_')) {
    fail(401, 'Missing or malformed API key. Pass it in the X-Api-Key header.');
  }
  const row = db.prepare(
    `SELECT k.id AS keyId, k.revoked_at, u.id AS userId, u.email, u.plan
       FROM api_keys k JOIN users u ON u.id = k.user_id
      WHERE k.key_hash = ?`
  ).get(sha256(rawKey));
  if (!row) fail(401, 'Invalid API key.');
  if (row.revoked_at) fail(401, 'This API key has been revoked.');

  const quota = QUOTAS[row.plan] || QUOTAS.free;
  const month = currentMonth();
  const used = db.prepare(
    'SELECT count FROM api_usage WHERE key_id = ? AND month = ?'
  ).get(row.keyId, month)?.count || 0;
  if (used >= quota) {
    fail(429, `Monthly quota of ${quota} scans reached for your ${row.plan} plan. Resets next month.`);
  }
  db.prepare(
    `INSERT INTO api_usage (key_id, month, count) VALUES (?, ?, 1)
     ON CONFLICT(key_id, month) DO UPDATE SET count = count + 1`
  ).run(row.keyId, month);

  return {
    keyId: row.keyId,
    user: { id: row.userId, email: row.email, plan: row.plan },
    quota,
    used: used + 1,
  };
}

function usageForUser(userId, plan) {
  const month = currentMonth();
  const total = db.prepare(
    `SELECT COALESCE(SUM(u.count), 0) AS n
       FROM api_usage u JOIN api_keys k ON k.id = u.key_id
      WHERE k.user_id = ? AND u.month = ?`
  ).get(userId, month).n;
  return { month, used: total, quota: QUOTAS[plan] || QUOTAS.free };
}

module.exports = { createKey, listKeys, revokeKey, authenticateKey, usageForUser, QUOTAS };
