const { test } = require('node:test');
const assert = require('node:assert');
const { _internal } = require('../lib/scanner');

const {
  registrableDomain, isIpHost, normalizeInput, editDistance, staticChecks, scoreFindings,
  gradeSecurityHeaders, fingerprintTechnology, isPrivateIp,
} = _internal;

function findingsFor(urlString) {
  const findings = [];
  staticChecks(new URL(urlString), findings);
  return findings;
}

const ids = (findings) => findings.map((f) => f.id);

test('registrableDomain handles plain and two-part TLDs', () => {
  assert.equal(registrableDomain('www.example.com'), 'example.com');
  assert.equal(registrableDomain('a.b.c.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.com'), 'example.com');
});

test('isIpHost detects IPv4', () => {
  assert.equal(isIpHost('192.168.1.1'), true);
  assert.equal(isIpHost('example.com'), false);
});

test('normalizeInput adds https and rejects junk', () => {
  assert.equal(normalizeInput('example.com'), 'https://example.com');
  assert.equal(normalizeInput('http://a.com'), 'http://a.com');
  assert.throws(() => normalizeInput(''), /enter a URL/);
  assert.throws(() => normalizeInput('has spaces.com/x y'), /spaces/);
});

test('editDistance counts substitutions and transpositions', () => {
  assert.equal(editDistance('google', 'google'), 0);
  assert.equal(editDistance('gooogle', 'google'), 1);
  assert.equal(editDistance('googel', 'google'), 1); // transposition
  assert.equal(editDistance('paypal', 'paypa1'), 1);
});

test('brand impersonation is flagged, official domains are not', () => {
  assert.ok(ids(findingsFor('https://paypal-secure-login.example.com/')).includes('brand-impersonation'));
  assert.ok(!ids(findingsFor('https://www.paypal.com/signin')).includes('brand-impersonation'));
});

test('brand aliases in subdomains are caught without flagging official sites', () => {
  // Real phishing patterns observed in live feeds.
  assert.ok(ids(findingsFor('https://validationoutlook365ing.site.je/')).includes('brand-impersonation'));
  assert.ok(ids(findingsFor('http://trezor.wallet-web3.com.cn/')).includes('brand-impersonation'));
  // Legitimate brand domains and subdomains must NOT trigger.
  assert.ok(!ids(findingsFor('https://www.microsoft.com/')).includes('brand-impersonation'));
  assert.ok(!ids(findingsFor('https://outlook.office.com/mail/')).includes('brand-impersonation'));
  assert.ok(!ids(findingsFor('https://trezor.io/')).includes('brand-impersonation'));
});

test('typosquats and wrong-TLD look-alikes are flagged', () => {
  assert.ok(ids(findingsFor('https://gooogle.com/')).includes('typosquat'));
  assert.ok(ids(findingsFor('https://paypal.top/')).includes('wrong-tld-lookalike'));
  assert.ok(!ids(findingsFor('https://google.com/')).some((id) => ['typosquat', 'wrong-tld-lookalike'].includes(id)));
});

test('dangerous schemes are critical', () => {
  const findings = findingsFor('javascript:alert(1)');
  assert.equal(findings[0].severity, 'critical');
});

test('IP hosts, shorteners, risky TLDs, punycode all detected', () => {
  assert.ok(ids(findingsFor('http://93.184.216.34/x')).includes('ip-host'));
  assert.ok(ids(findingsFor('https://bit.ly/abc')).includes('shortener'));
  assert.ok(ids(findingsFor('https://free-stuff.tk/')).includes('risky-tld'));
  assert.ok(ids(findingsFor('https://xn--pple-43d.com/')).includes('punycode'));
});

test('security headers are graded sensibly', () => {
  const all = new Headers({
    'strict-transport-security': 'max-age=63072000',
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=()',
  });
  assert.equal(gradeSecurityHeaders(all).grade, 'A');
  assert.equal(gradeSecurityHeaders(new Headers()).grade, 'F');
  const some = gradeSecurityHeaders(new Headers({ 'strict-transport-security': 'max-age=1', 'x-frame-options': 'DENY' }));
  assert.ok(['B', 'C'].includes(some.grade));
  assert.deepEqual(some.present, ['HSTS', 'X-Frame-Options']);
});

test('technology fingerprint detects server and stack', () => {
  const headers = new Headers({ server: 'nginx', 'x-powered-by': 'PHP/8.2' });
  const t = fingerprintTechnology(headers, '<link href="/wp-content/themes/x.css">');
  assert.equal(t.server, 'nginx');
  assert.equal(t.poweredBy, 'PHP/8.2');
  assert.ok(t.stack.includes('WordPress'));
  assert.equal(fingerprintTechnology(new Headers(), '<html></html>'), null);
});

test('private IP ranges are recognized', () => {
  for (const ip of ['10.0.0.1', '127.0.0.1', '192.168.1.5', '172.16.0.9', '169.254.1.1']) {
    assert.ok(isPrivateIp(ip), ip + ' should be private');
  }
  for (const ip of ['8.8.8.8', '93.184.216.34', '172.32.0.1']) {
    assert.ok(!isPrivateIp(ip), ip + ' should be public');
  }
});

test('scoring maps to verdicts at documented thresholds', () => {
  assert.equal(scoreFindings([{ severity: 'info' }]).verdict, 'safe');
  assert.equal(scoreFindings([{ severity: 'medium' }, { severity: 'low' }]).verdict, 'caution');
  assert.equal(scoreFindings([{ severity: 'high' }, { severity: 'medium' }, { severity: 'low' }]).verdict, 'dangerous');
  assert.equal(scoreFindings([{ severity: 'critical' }, { severity: 'critical' }]).score, 100);
});
