/**
 * Security middleware and helpers.
 *
 * Covers: security headers (CSP/HSTS/etc), HTTPS enforcement, request-body
 * hygiene, input validation, and bot protection for public forms.
 */

const crypto = require('crypto');

const isProd = () => process.env.NODE_ENV === 'production';

/* ---------------------------------------------------------------- */
/* Security headers                                                  */
/* ---------------------------------------------------------------- */

/**
 * Content-Security-Policy.
 *
 * script-src is strict ('self' only) — every page loads its JS from a file,
 * there are no inline <script> blocks or on* handlers anywhere.
 * style-src keeps 'unsafe-inline' because the pages use inline style
 * attributes for one-off layout; that is a far smaller risk than inline
 * script and does not enable code execution.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  // Destination screenshots are proxied from WordPress mShots.
  "img-src 'self' data: https://s.wordpress.com",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
  "manifest-src 'self'",
].join('; ');

function securityHeaders(req, res, next) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy',
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

  // Only meaningful (and only valid) over HTTPS.
  if (isSecureRequest(req)) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

/* ---------------------------------------------------------------- */
/* HTTPS enforcement                                                 */
/* ---------------------------------------------------------------- */

function isSecureRequest(req) {
  if (req.secure) return true;
  const proto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  return proto === 'https';
}

/** In production, redirect any plain-HTTP request to HTTPS. */
function forceHttps(req, res, next) {
  if (!isProd() || isSecureRequest(req)) return next();
  const host = req.headers.host;
  if (!host) return res.status(400).json({ error: 'Bad request.' });
  return res.redirect(301, `https://${host}${req.originalUrl}`);
}

/* ---------------------------------------------------------------- */
/* Request hygiene                                                   */
/* ---------------------------------------------------------------- */

/**
 * Rejects request bodies that are not JSON. The app has no file uploads and
 * no multipart/form-encoded endpoints, so anything else is refused outright.
 */
function jsonOnly(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const type = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (type === '' && !req.headers['content-length']) return next(); // bodyless DELETE
  if (type !== 'application/json') {
    return res.status(415).json({
      error: 'Unsupported content type. This API accepts application/json only.',
    });
  }
  next();
}

/* ---------------------------------------------------------------- */
/* Input validation                                                  */
/* ---------------------------------------------------------------- */

function badRequest(message) {
  const err = new Error(message);
  err.status = 400;
  err.expose = true;
  return err;
}

/** Returns a trimmed string, or throws if the value is not a sane string. */
function requireString(value, field, { max = 500, min = 1 } = {}) {
  if (typeof value !== 'string') throw badRequest(`"${field}" must be text.`);
  const trimmed = value.trim();
  if (trimmed.length < min) throw badRequest(`"${field}" is required.`);
  if (trimmed.length > max) throw badRequest(`"${field}" is too long (max ${max} characters).`);
  // Reject control characters that have no business in user input.
  for (const ch of trimmed) {
    const code = ch.codePointAt(0);
    if ((code < 32 && code !== 9) || code === 127) {
      throw badRequest(`"${field}" contains invalid characters.`);
    }
  }
  return trimmed;
}

/** Validates a list of URLs for bulk scanning. */
function requireUrlList(value, max) {
  if (!Array.isArray(value)) throw badRequest('"urls" must be a list.');
  if (value.length === 0) throw badRequest('Provide at least one URL.');
  if (value.length > max * 4) throw badRequest('Too many entries submitted.');
  const urls = [...new Set(value.map((u, i) => requireString(u, `urls[${i}]`, { max: 2048 })))];
  if (urls.length > max) {
    throw badRequest(
      `Please scan at most ${max} URLs per batch (you submitted ${urls.length}). ` +
      `Split the list and run it again — there's no limit on how many batches you can do.`
    );
  }
  return urls;
}

/** Public report ids are generated by us; reject anything oddly shaped. */
function requirePublicId(value) {
  const id = String(value || '');
  if (!/^[A-Za-z0-9_-]{4,32}$/.test(id)) throw badRequest('Invalid report id.');
  return id;
}

function requirePositiveInt(value, field) {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0 || n > Number.MAX_SAFE_INTEGER) {
    throw badRequest(`"${field}" must be a positive whole number.`);
  }
  return n;
}

/* ---------------------------------------------------------------- */
/* Bot protection                                                    */
/* ---------------------------------------------------------------- */

/**
 * Signed, time-limited form token. Issued when a signup/login page loads and
 * required back on submit, which blocks bots that POST directly to the API
 * without ever rendering the page, plus anything submitting implausibly fast.
 */
const FORM_SECRET = process.env.FORM_SECRET || crypto.randomBytes(32).toString('hex');
const FORM_MIN_AGE_MS = 1200;            // humans take longer than this to fill a form
const FORM_MAX_AGE_MS = 2 * 60 * 60 * 1000;

function issueFormToken() {
  const ts = Date.now().toString(36);
  const sig = crypto.createHmac('sha256', FORM_SECRET).update(ts).digest('base64url').slice(0, 32);
  return `${ts}.${sig}`;
}

function checkFormToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) {
    throw badRequest('Your form session expired. Please refresh the page and try again.');
  }
  const [ts, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', FORM_SECRET).update(ts).digest('base64url').slice(0, 32);
  const ok = sig.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  if (!ok) throw badRequest('Your form session was not valid. Please refresh the page and try again.');

  const age = Date.now() - parseInt(ts, 36);
  if (Number.isNaN(age) || age > FORM_MAX_AGE_MS) {
    throw badRequest('Your form session expired. Please refresh the page and try again.');
  }
  if (age < FORM_MIN_AGE_MS) {
    throw badRequest('That was submitted a little too quickly — please try again.');
  }
}

/**
 * Honeypot: the form renders a hidden field real users never see. Automated
 * form-fillers populate every input they find, so any value here is a bot.
 */
function checkHoneypot(body) {
  if (body && typeof body.website === 'string' && body.website.trim() !== '') {
    const err = new Error('Signup failed. Please try again.');
    err.status = 400;
    err.expose = true;
    err.bot = true;
    throw err;
  }
}

/** Runs every public-form bot check. */
function botCheck(body) {
  checkHoneypot(body);
  checkFormToken(body && body.formToken);
}

/* ---------------------------------------------------------------- */
/* Failed-login throttling (per account)                             */
/* ---------------------------------------------------------------- */

const failures = new Map();          // email -> { count, until }
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;

function assertNotLocked(email) {
  const rec = failures.get(email);
  if (rec && rec.until > Date.now()) {
    const mins = Math.ceil((rec.until - Date.now()) / 60000);
    const err = new Error(`Too many failed sign-in attempts. Try again in ${mins} minute${mins === 1 ? '' : 's'}.`);
    err.status = 429;
    err.expose = true;
    throw err;
  }
}

function recordFailure(email) {
  const rec = failures.get(email) || { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= MAX_FAILURES) {
    rec.until = Date.now() + LOCK_MS;
    rec.count = 0;
  }
  failures.set(email, rec);
  if (failures.size > 10000) failures.clear();
}

function clearFailures(email) {
  failures.delete(email);
}

module.exports = {
  securityHeaders, forceHttps, isSecureRequest, jsonOnly,
  requireString, requireUrlList, requirePublicId, requirePositiveInt, badRequest,
  issueFormToken, botCheck, checkFormToken, checkHoneypot,
  assertNotLocked, recordFailure, clearFailures,
  CSP,
};
