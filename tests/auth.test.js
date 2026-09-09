process.env.DATA_DIR = require('os').tmpdir() + '/linkaware-test-' + Date.now();

const { test } = require('node:test');
const assert = require('node:assert');
const auth = require('../lib/auth');
const apikeys = require('../lib/apikeys');

test('password hashing round-trips and rejects wrong passwords', () => {
  const hash = auth.hashPassword('correct horse battery');
  assert.ok(auth.verifyPassword('correct horse battery', hash));
  assert.ok(!auth.verifyPassword('wrong password', hash));
});

test('signup validates input and prevents duplicates', () => {
  const user = auth.signup('test@example.com', 'password123');
  assert.equal(user.email, 'test@example.com');
  assert.throws(() => auth.signup('test@example.com', 'password123'), /already exists/);
  assert.throws(() => auth.signup('not-an-email', 'password123'), /valid email/);
  assert.throws(() => auth.signup('short@example.com', 'short'), /8 characters/);
});

test('login succeeds with correct credentials only', () => {
  auth.signup('login@example.com', 'password123');
  const user = auth.login('login@example.com', 'password123');
  assert.equal(user.email, 'login@example.com');
  assert.throws(() => auth.login('login@example.com', 'wrongpass'), /Incorrect/);
  assert.throws(() => auth.login('ghost@example.com', 'password123'), /Incorrect/);
});

test('sessions authenticate and can be destroyed', () => {
  const user = auth.signup('session@example.com', 'password123');
  const token = auth.createSession(user.id);
  assert.equal(auth.userForSession(token).email, 'session@example.com');
  auth.destroySession(token);
  assert.equal(auth.userForSession(token), null);
});

test('API keys authenticate, count usage, and can be revoked', () => {
  const user = auth.signup('keys@example.com', 'password123');
  const { key } = apikeys.createKey(user.id, 'test');

  const first = apikeys.authenticateKey(key);
  assert.equal(first.used, 1);
  assert.equal(first.quota, apikeys.MONTHLY_QUOTA);
  assert.equal(apikeys.authenticateKey(key).used, 2);

  const listed = apikeys.listKeys(user.id);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].usedThisMonth, 2);

  apikeys.revokeKey(user.id, listed[0].id);
  assert.throws(() => apikeys.authenticateKey(key), /revoked/);
  assert.throws(() => apikeys.authenticateKey('lak_bogus'), /Invalid/);
});
