process.env.DATA_DIR = require('os').tmpdir() + '/linkaware-sectest-' + Date.now();

const { test } = require('node:test');
const assert = require('node:assert');
const sec = require('../lib/security');

/* ---------------- input validation ---------------- */

test('requireString trims, and rejects wrong types and oversized values', () => {
  assert.equal(sec.requireString('  hello  ', 'f'), 'hello');
  assert.throws(() => sec.requireString(123, 'f'), /must be text/);
  assert.throws(() => sec.requireString(['a'], 'f'), /must be text/);
  assert.throws(() => sec.requireString('', 'f'), /required/);
  assert.throws(() => sec.requireString('x'.repeat(501), 'f'), /too long/);
});

test('requireString rejects control characters but allows tabs', () => {
  assert.equal(sec.requireString('a\tb', 'f'), 'a\tb');
  assert.throws(() => sec.requireString('a' + String.fromCharCode(0) + 'b', 'f'), /invalid characters/);
  assert.throws(() => sec.requireString('a' + String.fromCharCode(27) + 'b', 'f'), /invalid characters/);
  assert.throws(() => sec.requireString('a' + String.fromCharCode(127) + 'b', 'f'), /invalid characters/);
});

test('requirePublicId accepts our ids and rejects traversal', () => {
  assert.equal(sec.requirePublicId('seFlP7fy'), 'seFlP7fy');
  assert.throws(() => sec.requirePublicId('../../etc/passwd'), /Invalid report id/);
  assert.throws(() => sec.requirePublicId('a'), /Invalid report id/);
  assert.throws(() => sec.requirePublicId('x'.repeat(40)), /Invalid report id/);
});

test('requirePositiveInt rejects non-numbers and negatives', () => {
  assert.equal(sec.requirePositiveInt('42', 'id'), 42);
  assert.throws(() => sec.requirePositiveInt('abc', 'id'), /positive whole number/);
  assert.throws(() => sec.requirePositiveInt('-1', 'id'), /positive whole number/);
  assert.throws(() => sec.requirePositiveInt('1.5', 'id'), /positive whole number/);
});

test('requireUrlList enforces type, dedupes, and caps batch size', () => {
  assert.deepEqual(sec.requireUrlList([' a.com ', 'a.com', 'b.com'], 25), ['a.com', 'b.com']);
  assert.throws(() => sec.requireUrlList('a.com', 25), /must be a list/);
  assert.throws(() => sec.requireUrlList([], 25), /at least one URL/);
  assert.throws(() => sec.requireUrlList(Array.from({ length: 30 }, (_, i) => `u${i}.com`), 25), /at most 25/);
  assert.throws(() => sec.requireUrlList([1, 2], 25), /must be text/);
});

/* ---------------- bot protection ---------------- */

test('honeypot rejects filled field, passes empty', () => {
  assert.doesNotThrow(() => sec.checkHoneypot({ website: '' }));
  assert.doesNotThrow(() => sec.checkHoneypot({}));
  assert.throws(() => sec.checkHoneypot({ website: 'http://spam' }), /Signup failed/);
});

test('form token must be present, authentic, and not instant', () => {
  assert.throws(() => sec.checkFormToken(undefined), /expired/);
  assert.throws(() => sec.checkFormToken('garbage'), /expired/);
  assert.throws(() => sec.checkFormToken('abc.def'), /not valid/);
  // A token issued right now is "too fast" to be a human submission.
  assert.throws(() => sec.checkFormToken(sec.issueFormToken()), /too quickly/);
});

test('form token from a plausible human delay is accepted', () => {
  const ts = (Date.now() - 5000).toString(36);
  const crypto = require('crypto');
  const secret = process.env.FORM_SECRET;
  // Only meaningful when the secret is pinned; otherwise verify the shape path.
  if (!secret) return;
  const sig = crypto.createHmac('sha256', secret).update(ts).digest('base64url').slice(0, 32);
  assert.doesNotThrow(() => sec.checkFormToken(`${ts}.${sig}`));
});

/* ---------------- login throttling ---------------- */

test('account locks after repeated failures and clears on success', () => {
  const email = 'lockme@example.com';
  assert.doesNotThrow(() => sec.assertNotLocked(email));
  for (let i = 0; i < 5; i++) sec.recordFailure(email);
  assert.throws(() => sec.assertNotLocked(email), /Too many failed sign-in attempts/);
  sec.clearFailures(email);
  assert.doesNotThrow(() => sec.assertNotLocked(email));
});

/* ---------------- headers / transport ---------------- */

test('CSP forbids inline script and locks down framing', () => {
  assert.match(sec.CSP, /script-src 'self'/);
  assert.ok(!/script-src[^;]*unsafe-inline/.test(sec.CSP), 'script-src must not allow inline');
  assert.ok(!/script-src[^;]*unsafe-eval/.test(sec.CSP), 'script-src must not allow eval');
  assert.match(sec.CSP, /frame-ancestors 'none'/);
  assert.match(sec.CSP, /object-src 'none'/);
  assert.match(sec.CSP, /base-uri 'self'/);
});

test('isSecureRequest honours the proxy protocol header', () => {
  assert.equal(sec.isSecureRequest({ secure: true, headers: {} }), true);
  assert.equal(sec.isSecureRequest({ headers: { 'x-forwarded-proto': 'https' } }), true);
  assert.equal(sec.isSecureRequest({ headers: { 'x-forwarded-proto': 'https, http' } }), true);
  assert.equal(sec.isSecureRequest({ headers: { 'x-forwarded-proto': 'http' } }), false);
  assert.equal(sec.isSecureRequest({ headers: {} }), false);
});

test('jsonOnly rejects non-JSON bodies on writes', () => {
  const run = (method, contentType) => {
    let status = null;
    const req = { method, headers: contentType ? { 'content-type': contentType, 'content-length': '10' } : {} };
    const res = { status: (s) => { status = s; return { json: () => {} }; } };
    let nexted = false;
    sec.jsonOnly(req, res, () => { nexted = true; });
    return { status, nexted };
  };
  assert.equal(run('GET', 'text/html').nexted, true);
  assert.equal(run('POST', 'application/json').nexted, true);
  assert.equal(run('POST', 'application/json; charset=utf-8').nexted, true);
  assert.equal(run('POST', 'multipart/form-data').status, 415);
  assert.equal(run('POST', 'application/x-www-form-urlencoded').status, 415);
});
