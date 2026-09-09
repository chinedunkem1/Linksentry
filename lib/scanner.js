/**
 * Linkaware scan engine.
 *
 * Layered analysis:
 *   1. Static URL heuristics (structure, host, keywords) — always available.
 *   2. Live network checks — redirect chain, HTTPS reachability.
 *   3. Domain intelligence — registration age via public RDAP.
 *   4. Optional threat feeds — Google Safe Browsing / VirusTotal when API
 *      keys are present in the environment (GSB_API_KEY / VT_API_KEY).
 *
 * Each check emits findings with a severity weight; the total maps to a
 * verdict: safe (<25), caution (25–59), dangerous (>=60).
 */

const tls = require('tls');
const dns = require('dns').promises;

const SEVERITY_WEIGHT = { info: 0, low: 8, medium: 18, high: 40, critical: 70 };

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc',
  'lnkd.in', 's.id', 'v.gd', 'qr.ae', 'adf.ly', 'bl.ink', 'soo.gd',
]);

const RISKY_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov', 'top', 'click', 'icu',
  'buzz', 'rest', 'surf', 'cam', 'monster', 'quest', 'cfd', 'sbs',
  'lol', 'work', 'loan', 'men', 'gdn', 'bid', 'stream',
]);

const PHISH_KEYWORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification',
  'secure', 'security', 'account', 'update', 'confirm', 'banking',
  'wallet', 'password', 'authenticate', 'recover', 'unlock', 'suspended',
  'validation', 'validate', 'billing', 'payment', 'invoice', 'restricted',
];

/**
 * Brand impersonation targets. `tokens` are the strings that, when they
 * appear in a hostname, suggest the brand is being referenced (including
 * common aliases). `domains` are the brand's legitimate registrable domains.
 */
const IMPERSONATED_BRANDS = [
  { brand: 'PayPal', tokens: ['paypal'], domains: ['paypal.com', 'paypal.me'] },
  { brand: 'Apple', tokens: ['apple', 'icloud', 'appleid'], domains: ['apple.com', 'icloud.com'] },
  { brand: 'Microsoft', tokens: ['microsoft', 'outlook', 'office365', 'microsoft365', 'onedrive', 'mslogin', 'windowslive'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'msn.com', 'sharepoint.com'] },
  { brand: 'Amazon', tokens: ['amazon', 'awslogin'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'aws.amazon.com'] },
  { brand: 'Netflix', tokens: ['netflix'], domains: ['netflix.com'] },
  { brand: 'Google', tokens: ['google', 'gmail', 'googledrive'], domains: ['google.com', 'gmail.com', 'youtube.com', 'goo.gl'] },
  { brand: 'Facebook', tokens: ['facebook', 'faceb00k'], domains: ['facebook.com', 'fb.com', 'meta.com'] },
  { brand: 'Instagram', tokens: ['instagram'], domains: ['instagram.com'] },
  { brand: 'WhatsApp', tokens: ['whatsapp'], domains: ['whatsapp.com'] },
  { brand: 'Coinbase', tokens: ['coinbase'], domains: ['coinbase.com'] },
  { brand: 'Binance', tokens: ['binance'], domains: ['binance.com'] },
  { brand: 'MetaMask', tokens: ['metamask'], domains: ['metamask.io'] },
  { brand: 'Trezor', tokens: ['trezor'], domains: ['trezor.io'] },
  { brand: 'Ledger', tokens: ['ledger'], domains: ['ledger.com'] },
  { brand: 'Exodus wallet', tokens: ['exodus'], domains: ['exodus.com'] },
  { brand: 'Chase', tokens: ['chase'], domains: ['chase.com'] },
  { brand: 'Wells Fargo', tokens: ['wellsfargo'], domains: ['wellsfargo.com'] },
  { brand: 'Bank of America', tokens: ['bankofamerica', 'bofa'], domains: ['bankofamerica.com'] },
  { brand: 'DHL', tokens: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
  { brand: 'FedEx', tokens: ['fedex'], domains: ['fedex.com'] },
  { brand: 'USPS', tokens: ['usps'], domains: ['usps.com'] },
  { brand: 'LinkedIn', tokens: ['linkedin'], domains: ['linkedin.com'] },
  { brand: 'Steam', tokens: ['steamcommunity', 'steampowered'], domains: ['steampowered.com', 'steamcommunity.com'] },
];

/* Popular targets for typosquatting: registrable name → official domain. */
const POPULAR_DOMAINS = [
  ['google', 'google.com'], ['youtube', 'youtube.com'], ['facebook', 'facebook.com'],
  ['instagram', 'instagram.com'], ['twitter', 'twitter.com'], ['amazon', 'amazon.com'],
  ['wikipedia', 'wikipedia.org'], ['reddit', 'reddit.com'], ['netflix', 'netflix.com'],
  ['microsoft', 'microsoft.com'], ['apple', 'apple.com'], ['linkedin', 'linkedin.com'],
  ['paypal', 'paypal.com'], ['ebay', 'ebay.com'], ['spotify', 'spotify.com'],
  ['whatsapp', 'whatsapp.com'], ['tiktok', 'tiktok.com'], ['discord', 'discord.com'],
  ['github', 'github.com'], ['dropbox', 'dropbox.com'], ['adobe', 'adobe.com'],
  ['zoom', 'zoom.us'], ['coinbase', 'coinbase.com'], ['binance', 'binance.com'],
  ['chase', 'chase.com'], ['wellsfargo', 'wellsfargo.com'], ['bankofamerica', 'bankofamerica.com'],
  ['walmart', 'walmart.com'], ['target', 'target.com'], ['steam', 'steampowered.com'],
  ['roblox', 'roblox.com'], ['telegram', 'telegram.org'], ['outlook', 'outlook.com'],
  ['gmail', 'gmail.com'], ['icloud', 'icloud.com'], ['yahoo', 'yahoo.com'],
  ['fedex', 'fedex.com'], ['usps', 'usps.com'], ['dhl', 'dhl.com'], ['ups', 'ups.com'],
];

const TWO_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
  'co.nz', 'co.jp', 'com.br', 'com.mx', 'co.in', 'com.sg', 'com.ng',
  'co.za', 'com.tr', 'com.cn', 'com.hk',
]);

function registrableDomain(hostname) {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname.toLowerCase();
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

function isIpHost(hostname) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  return hostname.startsWith('[') || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(hostname);
}

/** Validation errors that are safe to show the user verbatim. */
function inputError(message, status = 400) {
  const err = new Error(message);
  err.status = status;
  err.expose = true;
  return err;
}

function normalizeInput(raw) {
  let input = String(raw || '').trim();
  if (!input) throw inputError('Please enter a URL to scan.');
  if (input.length > 2048) throw inputError('URL is too long (max 2048 characters).');
  if (/\s/.test(input)) throw inputError('URLs cannot contain spaces. Please check your input.');
  if (!/^[a-z][a-z0-9+.-]*:/i.test(input)) input = 'https://' + input;
  return input;
}

function fetchWithTimeout(url, options = {}, ms = 8000) {
  return fetch(url, {
    ...options,
    signal: AbortSignal.timeout(ms),
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; LinkawareBot/1.0; +https://linkaware.app)',
      'Accept': '*/*',
      ...(options.headers || {}),
    },
  });
}

/** Damerau–Levenshtein distance (with transpositions). */
function editDistance(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 2) return 99;
  const d = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array(n + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

function typosquatCheck(regDomain, findings) {
  const name = regDomain.split('.')[0];
  for (const [popular, official] of POPULAR_DOMAINS) {
    if (regDomain === official) return; // it IS the official site
    if (name === popular) {
      findings.push({
        id: 'wrong-tld-lookalike', severity: 'high',
        title: `Look-alike of ${official}`,
        detail: `"${regDomain}" uses the well-known name "${popular}" on a different domain extension. The real site is ${official} — anyone can register the same name under another extension.`,
      });
      return;
    }
    const maxDist = popular.length >= 8 ? 2 : 1;
    const dist = editDistance(name, popular);
    if (dist > 0 && dist <= maxDist) {
      findings.push({
        id: 'typosquat', severity: 'high',
        title: `Possible typosquat of ${official}`,
        detail: `"${regDomain}" is only ${dist} character${dist === 1 ? '' : 's'} away from ${official}. Misspelled look-alike domains are registered specifically to catch typing mistakes and disguise phishing links.`,
      });
      return;
    }
  }
}

/* ---------------------------------------------------------------- */
/* Static heuristics                                                 */
/* ---------------------------------------------------------------- */

function staticChecks(url, findings) {
  const host = url.hostname.toLowerCase();
  const full = url.href;

  if (url.protocol === 'javascript:' || url.protocol === 'data:' || url.protocol === 'vbscript:') {
    findings.push({
      id: 'dangerous-scheme', severity: 'critical', title: 'Dangerous URL scheme',
      detail: `This link uses the "${url.protocol}" scheme, which executes code directly in your browser. Never open links like this.`,
    });
    return;
  }

  if (url.protocol === 'http:') {
    findings.push({
      id: 'no-https', severity: 'medium', title: 'Not encrypted (HTTP)',
      detail: 'The link uses plain HTTP. Anything you type on this page — passwords, card numbers — can be intercepted in transit.',
    });
  } else if (url.protocol === 'https:') {
    findings.push({
      id: 'https', severity: 'info', title: 'Uses HTTPS',
      detail: 'The connection to this site is encrypted. Note that HTTPS alone does not guarantee the site is trustworthy.',
    });
  }

  if (isIpHost(host)) {
    findings.push({
      id: 'ip-host', severity: 'high', title: 'Raw IP address instead of a domain',
      detail: 'Legitimate services almost never link to a bare IP address. This is a common trait of phishing and malware distribution.',
    });
    return;
  }

  if (host.split('.').some((p) => p.startsWith('xn--'))) {
    findings.push({
      id: 'punycode', severity: 'high', title: 'Internationalized (punycode) domain',
      detail: 'The domain uses encoded international characters. Attackers use look-alike characters (e.g. "аpple.com" with a Cyrillic "а") to impersonate real brands.',
    });
  }

  if (url.username || full.includes('@') && full.indexOf('@') < full.indexOf(host)) {
    findings.push({
      id: 'userinfo', severity: 'high', title: 'Embedded "@" credentials trick',
      detail: 'The URL contains an "@" before the real domain. Everything before the "@" is a decoy — the browser actually visits what comes after it.',
    });
  }

  const regDomain = registrableDomain(host);
  const tld = regDomain.split('.').pop();

  if (SHORTENERS.has(regDomain)) {
    findings.push({
      id: 'shortener', severity: 'medium', title: 'Link shortener detected',
      detail: `${regDomain} hides the real destination. Linkaware will follow the redirect chain to reveal where it actually leads.`,
    });
  }

  if (RISKY_TLDS.has(tld)) {
    findings.push({
      id: 'risky-tld', severity: 'medium', title: `High-abuse domain extension (.${tld})`,
      detail: `The .${tld} extension is disproportionately used in spam and phishing campaigns because registrations are cheap or free.`,
    });
  }

  const subdomainCount = host.split('.').length - regDomain.split('.').length;
  if (subdomainCount >= 3) {
    findings.push({
      id: 'deep-subdomains', severity: 'medium', title: 'Unusually deep subdomain nesting',
      detail: `${subdomainCount} subdomain levels detected. Attackers stack subdomains (e.g. "paypal.com.secure-login.example.com") so the fake brand shows first on small screens.`,
    });
  }

  // Brand impersonation: a brand token appearing anywhere in the hostname
  // while the host is not an official domain for that brand.
  const hostAlnum = host.replace(/[^a-z0-9]/g, '');
  for (const { brand, tokens, domains } of IMPERSONATED_BRANDS) {
    const isOfficial = domains.some((d) => regDomain === d || host === d || host.endsWith('.' + d));
    if (isOfficial) continue;
    const matched = tokens.find((tok) => host.includes(tok) || hostAlnum.includes(tok));
    if (!matched) continue;

    // Stronger signal when the brand token is part of the registrable domain
    // itself, or paired with credential-bait wording anywhere in the host.
    const inRegistrable = registrableDomain(host).replace(/[^a-z0-9]/g, '').includes(matched);
    const withBait = PHISH_KEYWORDS.some((k) => host.includes(k));
    const severity = (inRegistrable || withBait) ? 'high' : 'medium';
    findings.push({
      id: 'brand-impersonation', severity,
      title: `Possible ${brand} impersonation`,
      detail: `The address references "${matched}" but is not an official ${brand} domain (${domains[0]}). Impersonating a trusted brand in the hostname — whether in the domain or a subdomain — is the most common phishing pattern.`,
    });
    break;
  }

  typosquatCheck(regDomain, findings);

  const keywordHits = PHISH_KEYWORDS.filter((k) => host.includes(k));
  if (keywordHits.length > 0) {
    findings.push({
      id: 'phish-keywords', severity: keywordHits.length > 1 ? 'medium' : 'low',
      title: 'Credential-bait wording in the domain',
      detail: `The domain itself contains ${keywordHits.map((k) => `"${k}"`).join(', ')}. Real companies put these words in the page, not in throwaway domain names.`,
    });
  }

  const hyphens = (regDomain.match(/-/g) || []).length;
  if (hyphens >= 3) {
    findings.push({
      id: 'many-hyphens', severity: 'low', title: 'Excessive hyphens in domain',
      detail: 'Domains with many hyphens are strongly correlated with machine-generated phishing infrastructure.',
    });
  }

  if (url.port && !['80', '443', ''].includes(url.port)) {
    findings.push({
      id: 'odd-port', severity: 'medium', title: `Non-standard port (:${url.port})`,
      detail: 'Legitimate public websites serve on ports 80/443. Unusual ports often indicate makeshift or compromised servers.',
    });
  }

  const pctEncoded = (full.match(/%[0-9a-f]{2}/gi) || []).length;
  if (pctEncoded > 10) {
    findings.push({
      id: 'heavy-encoding', severity: 'low', title: 'Heavily encoded URL',
      detail: `${pctEncoded} percent-encoded sequences found. Excessive encoding is sometimes used to disguise a malicious payload or destination.`,
    });
  }

  if (full.length > 150) {
    findings.push({
      id: 'very-long', severity: 'low', title: 'Unusually long URL',
      detail: `${full.length} characters. Extremely long URLs are used to push the real domain out of view in the address bar.`,
    });
  }
}

/* ---------------------------------------------------------------- */
/* Redirect chain                                                    */
/* ---------------------------------------------------------------- */

async function followRedirects(startUrl, findings) {
  const chain = [{ url: startUrl.href, status: null }];
  let current = new URL(startUrl.href);
  let reachable = false;

  for (let hop = 0; hop < 8; hop++) {
    let res;
    try {
      res = await fetchWithTimeout(current.href, { method: 'HEAD', redirect: 'manual' }, 7000);
      if (res.status === 405 || res.status === 501) {
        res = await fetchWithTimeout(current.href, { method: 'GET', redirect: 'manual' }, 7000);
      }
    } catch (err) {
      if (hop === 0) {
        findings.push({
          id: 'unreachable', severity: 'medium', title: 'Site did not respond',
          detail: 'The server could not be reached (offline, blocking scanners, or the domain may not exist). Treat unreachable links from unsolicited messages with extra suspicion.',
        });
      }
      return { chain, finalUrl: current.href, reachable };
    }

    reachable = true;
    chain[chain.length - 1].status = res.status;

    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      let next;
      try {
        next = new URL(location, current.href);
      } catch {
        break;
      }
      chain.push({ url: next.href, status: null });
      current = next;
      continue;
    }
    break;
  }

  if (chain.length > 4) {
    findings.push({
      id: 'long-redirect-chain', severity: 'medium', title: `Long redirect chain (${chain.length - 1} hops)`,
      detail: 'Multiple chained redirects are commonly used to evade blocklists and email scanners.',
    });
  }

  const startDomain = registrableDomain(startUrl.hostname);
  const finalHost = new URL(current.href).hostname;
  // Shorteners redirecting cross-domain is their normal function — the
  // shortener finding already covers it, so don't double-penalize.
  if (!isIpHost(finalHost) && registrableDomain(finalHost) !== startDomain &&
      chain.length > 1 && !SHORTENERS.has(startDomain)) {
    findings.push({
      id: 'cross-domain-redirect', severity: 'medium', title: 'Redirects to a different domain',
      detail: `The link you were given (${startDomain}) silently forwards to ${registrableDomain(finalHost)}. Judge the destination, not the link you received.`,
    });
  }

  if (chain.length > 1 && current.protocol === 'http:') {
    findings.push({
      id: 'downgrade', severity: 'high', title: 'Redirects to an unencrypted page',
      detail: 'The redirect chain ends on plain HTTP — a downgrade that exposes anything you submit.',
    });
  }

  return { chain, finalUrl: current.href, reachable };
}

/* ---------------------------------------------------------------- */
/* TLS certificate inspection                                        */
/* ---------------------------------------------------------------- */

function tlsCheck(hostname, port, findings) {
  return new Promise((resolve) => {
    if (isIpHost(hostname)) return resolve(null);
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* already closed */ }
      resolve(value);
    };
    const socket = tls.connect(
      { host: hostname, port: port || 443, servername: hostname, rejectUnauthorized: false, timeout: 6000 },
      () => {
        const cert = socket.getPeerCertificate();
        if (!cert || !cert.valid_to) return done(null);

        const validTo = new Date(cert.valid_to);
        const daysLeft = Math.floor((validTo.getTime() - Date.now()) / 86400000);
        const issuer = cert.issuer?.O || cert.issuer?.CN || 'unknown issuer';
        const selfSigned = !socket.authorized &&
          ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(socket.authorizationError);

        if (daysLeft < 0) {
          findings.push({
            id: 'cert-expired', severity: 'high', title: 'Expired security certificate',
            detail: `The site's TLS certificate expired ${-daysLeft} day${daysLeft === -1 ? '' : 's'} ago. Legitimate operators renew certificates; expired ones suggest an abandoned or careless site.`,
          });
        } else if (selfSigned) {
          findings.push({
            id: 'cert-self-signed', severity: 'high', title: 'Self-signed certificate',
            detail: 'The certificate was not issued by a trusted authority — the encryption cannot be verified and the site identity is unproven.',
          });
        } else if (!socket.authorized) {
          findings.push({
            id: 'cert-invalid', severity: 'medium', title: 'Certificate could not be verified',
            detail: `The TLS certificate failed validation (${socket.authorizationError}). Browsers will show a warning on this site.`,
          });
        } else {
          findings.push({
            id: 'cert-valid', severity: 'info', title: `Valid certificate (issued by ${issuer})`,
            detail: `The TLS certificate is valid${daysLeft <= 400 ? ` and expires in ${daysLeft} days` : ''}. Note: attackers can obtain free valid certificates too, so this alone is not proof of legitimacy.`,
          });
        }
        done({ issuer, validTo: validTo.toISOString().slice(0, 10), authorized: socket.authorized });
      }
    );
    socket.on('timeout', () => done(null));
    socket.on('error', () => done(null));
  });
}

/* ---------------------------------------------------------------- */
/* Page content analysis                                             */
/* ---------------------------------------------------------------- */

async function contentChecks(finalUrl, findings) {
  const url = new URL(finalUrl);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  let res;
  try {
    res = await fetchWithTimeout(finalUrl, { method: 'GET' }, 8000);
  } catch {
    return null;
  }
  const securityHeaders = gradeSecurityHeaders(res.headers);
  const type = res.headers.get('content-type') || '';
  if (!type.includes('text/html')) {
    if (/octet-stream|application\/(x-msdownload|x-msdos-program|zip|x-rar)/i.test(type)) {
      findings.push({
        id: 'direct-download', severity: 'medium', title: 'Link serves a direct file download',
        detail: `The destination responds with "${type.split(';')[0]}" instead of a web page. Unexpected file downloads are a common malware delivery method.`,
      });
    }
    try { await res.body?.cancel(); } catch { /* ignore */ }
    return { title: null, securityHeaders, technology: fingerprintTechnology(res.headers, '') };
  }

  let html = '';
  try {
    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: false });
    while (html.length < 300000) {
      const { done, value } = await reader.read();
      if (done) break;
      html += decoder.decode(value, { stream: true });
    }
    try { await reader.cancel(); } catch { /* stream already ended */ }
  } catch {
    return null;
  }

  const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim().replace(/\s+/g, ' ').slice(0, 140) : null;

  const hasRiskContext = findings.some((f) => f.severity === 'high' || f.severity === 'critical');

  if (/<input[^>]+type\s*=\s*["']?password/i.test(html)) {
    findings.push({
      id: 'password-form',
      severity: hasRiskContext ? 'medium' : 'info',
      title: 'Page asks for a password',
      detail: hasRiskContext
        ? 'The destination contains a password form and this link already shows other risk indicators — a classic credential-harvesting setup. Do not enter credentials here.'
        : 'The destination contains a login form. Make sure the address bar shows the exact site you expect before signing in.',
    });
  }

  const metaRefresh = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)/i);
  if (metaRefresh) {
    findings.push({
      id: 'meta-refresh', severity: 'medium', title: 'Hidden page-level redirect',
      detail: `The page silently forwards visitors to "${metaRefresh[1].slice(0, 120)}" using a meta-refresh tag — a technique used to slip past link scanners that only check HTTP redirects.`,
    });
  }

  return { title, securityHeaders, technology: fingerprintTechnology(res.headers, html) };
}

/* ---------------------------------------------------------------- */
/* Domain age via RDAP                                               */
/* ---------------------------------------------------------------- */

async function domainAge(hostname, findings) {
  if (isIpHost(hostname)) return null;
  const domain = registrableDomain(hostname);
  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {}, 7000);
    if (!res.ok) return null;
    const data = await res.json();
    const reg = (data.events || []).find((e) => e.eventAction === 'registration');
    if (!reg || !reg.eventDate) return null;

    const registered = new Date(reg.eventDate);
    const days = Math.floor((Date.now() - registered.getTime()) / 86400000);
    const info = { domain, registered: registered.toISOString().slice(0, 10), ageDays: days };

    // Registrar (entity with the "registrar" role)
    const registrarEntity = (data.entities || []).find((e) => (e.roles || []).includes('registrar'));
    if (registrarEntity) {
      const vcard = registrarEntity.vcardArray?.[1] || [];
      const fn = vcard.find((f) => f[0] === 'fn');
      info.registrar = fn ? fn[3] : (registrarEntity.handle || null);
    }

    // Nameservers
    if (Array.isArray(data.nameservers) && data.nameservers.length) {
      info.nameservers = data.nameservers.map((ns) => (ns.ldhName || '').toLowerCase()).filter(Boolean).slice(0, 4);
    }

    // Registrant country
    const registrant = (data.entities || []).find((e) => (e.roles || []).includes('registrant'));
    const rcard = registrant?.vcardArray?.[1] || [];
    const adr = rcard.find((f) => f[0] === 'adr');
    if (adr && Array.isArray(adr[3])) info.country = adr[3][adr[3].length - 1] || null;

    // Expiry
    const exp = (data.events || []).find((e) => e.eventAction === 'expiration');
    if (exp && exp.eventDate) {
      const expDate = new Date(exp.eventDate);
      info.expires = expDate.toISOString().slice(0, 10);
      const daysToExpiry = Math.floor((expDate.getTime() - Date.now()) / 86400000);
      if (daysToExpiry < 0) {
        findings.push({
          id: 'domain-expired', severity: 'medium', title: 'Domain registration has lapsed',
          detail: 'The domain registration expired and may be in a grace/redemption period — ownership can change hands. Be cautious.',
        });
      }
    }

    if (days < 30) {
      findings.push({
        id: 'brand-new-domain', severity: 'high', title: `Domain registered ${days} day${days === 1 ? '' : 's'} ago`,
        detail: 'Freshly registered domains are the strongest single phishing indicator — attack sites are typically spun up days before a campaign and burned after.',
      });
    } else if (days < 180) {
      findings.push({
        id: 'young-domain', severity: 'medium', title: `Young domain (registered ${info.registered})`,
        detail: 'This domain is less than six months old. Established businesses rarely operate on brand-new domains.',
      });
    } else if (days > 365 * 3) {
      findings.push({
        id: 'established-domain', severity: 'info', title: `Established domain (registered ${info.registered})`,
        detail: `This domain has existed for over ${Math.floor(days / 365)} years, which is a positive trust signal.`,
      });
    }
    return info;
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------- */
/* DNS + hosting / geolocation intelligence                          */
/* ---------------------------------------------------------------- */

function isPrivateIp(ip) {
  return /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) ||
    /^(::1|fc|fd|fe80)/i.test(ip);
}

async function dnsAndHosting(hostname, findings) {
  if (isIpHost(hostname)) {
    return lookupIpInfo(hostname.replace(/[[\]]/g, ''));
  }
  let ips = [];
  try {
    // dns.lookup uses the OS resolver (works behind VPNs/filtered networks
    // where direct resolver queries are blocked).
    const records = await dns.lookup(hostname, { all: true });
    ips = records.map((r) => r.address);
  } catch { /* unresolved */ }
  if (ips.length === 0) {
    findings.push({
      id: 'no-dns', severity: 'medium', title: 'Domain does not resolve',
      detail: 'This hostname has no DNS records, so it points nowhere right now. Dead domains in messages are often abandoned scam infrastructure or typos.',
    });
    return null;
  }
  if (ips.some(isPrivateIp)) {
    findings.push({
      id: 'private-ip', severity: 'high', title: 'Resolves to a private/internal address',
      detail: 'The domain points at a private network address. This can be an attempt at DNS-rebinding to reach devices inside your network.',
    });
  }
  const info = await lookupIpInfo(ips[0]);
  if (info) info.ips = ips.slice(0, 4);
  return info;
}

async function lookupIpInfo(ip) {
  try {
    const res = await fetchWithTimeout(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,city,isp,org,as,reverse,hosting`,
      {}, 6000
    );
    if (!res.ok) return { ip, ips: [ip] };
    const d = await res.json();
    if (d.status !== 'success') return { ip, ips: [ip] };
    return {
      ip, ips: [ip],
      country: d.country || null,
      countryCode: d.countryCode || null,
      city: d.city || null,
      org: d.org || d.isp || null,
      asn: d.as || null,
      reverse: d.reverse || null,
      hosting: Boolean(d.hosting),
    };
  } catch {
    return { ip, ips: [ip] };
  }
}

/* ---------------------------------------------------------------- */
/* HTTP security-header grading                                      */
/* ---------------------------------------------------------------- */

const SECURITY_HEADERS = [
  { key: 'strict-transport-security', label: 'HSTS', weight: 3 },
  { key: 'content-security-policy', label: 'Content-Security-Policy', weight: 3 },
  { key: 'x-frame-options', label: 'X-Frame-Options', weight: 2 },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 1 },
  { key: 'referrer-policy', label: 'Referrer-Policy', weight: 1 },
  { key: 'permissions-policy', label: 'Permissions-Policy', weight: 1 },
];

function gradeSecurityHeaders(headers) {
  const present = [];
  const missing = [];
  let earned = 0;
  let total = 0;
  for (const h of SECURITY_HEADERS) {
    total += h.weight;
    if (headers.get(h.key)) { present.push(h.label); earned += h.weight; }
    else missing.push(h.label);
  }
  const ratio = earned / total;
  const grade = ratio >= 0.85 ? 'A' : ratio >= 0.6 ? 'B' : ratio >= 0.35 ? 'C' : ratio > 0 ? 'D' : 'F';
  return { grade, present, missing };
}

/* ---------------------------------------------------------------- */
/* Technology / server fingerprint                                   */
/* ---------------------------------------------------------------- */

const TECH_SIGNATURES = [
  { name: 'WordPress', re: /wp-content|wp-includes|<meta[^>]+WordPress/i },
  { name: 'Shopify', re: /cdn\.shopify\.com|Shopify\.theme/i },
  { name: 'Wix', re: /wix\.com|X-Wix|static\.wixstatic/i },
  { name: 'Squarespace', re: /squarespace\.com|static1\.squarespace/i },
  { name: 'Webflow', re: /webflow\.(io|com)|data-wf-page/i },
  { name: 'Drupal', re: /Drupal\.settings|sites\/all\/|sites\/default\/files/i },
  { name: 'Joomla', re: /\/media\/jui\/|Joomla!/i },
  { name: 'React', re: /__NEXT_DATA__|data-reactroot|react\.production/i },
  { name: 'Cloudflare', re: /cloudflare|cf-ray/i },
];

function fingerprintTechnology(headers, html) {
  const stack = [];
  const server = headers.get('server') || null;
  const poweredBy = headers.get('x-powered-by') || null;
  const cfRay = headers.get('cf-ray');
  const body = html || '';
  for (const sig of TECH_SIGNATURES) {
    if (sig.re.test(body) || (sig.name === 'Cloudflare' && cfRay)) stack.push(sig.name);
  }
  if (!stack.length && !server && !poweredBy) return null;
  return { server, poweredBy, stack: [...new Set(stack)] };
}

/* ---------------------------------------------------------------- */
/* Optional URLhaus reputation (abuse.ch) — needs URLHAUS_API_KEY    */
/* ---------------------------------------------------------------- */

async function urlhausLookup(hostname, findings) {
  const key = process.env.URLHAUS_API_KEY;
  if (!key || isIpHost(hostname)) return null;
  try {
    const res = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Auth-Key': key },
      body: `host=${encodeURIComponent(hostname)}`,
    }, 7000);
    if (!res.ok) return null;
    const data = await res.json();
    if (data.query_status !== 'ok') return { checked: true, flagged: false };
    const active = (data.urls || []).filter((u) => u.url_status === 'online').length;
    if (data.urls && data.urls.length > 0) {
      findings.push({
        id: 'urlhaus-flagged', severity: 'critical', title: 'Listed on URLhaus (abuse.ch)',
        detail: `abuse.ch's malware-URL database has ${data.urls.length} record(s) for this host${active ? `, ${active} still active` : ''}. This host is associated with malware distribution.`,
      });
      return { checked: true, flagged: true };
    }
    return { checked: true, flagged: false };
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------- */
/* Optional threat-intelligence feeds                                */
/* ---------------------------------------------------------------- */

async function googleSafeBrowsing(urlsToCheck, findings) {
  const key = process.env.GSB_API_KEY;
  if (!key) return null;
  try {
    const res = await fetchWithTimeout(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'Linkaware', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: urlsToCheck.map((u) => ({ url: u })),
          },
        }),
      },
      8000
    );
    if (!res.ok) return null;
    const data = await res.json();
    if (data.matches && data.matches.length > 0) {
      const types = [...new Set(data.matches.map((m) => m.threatType.replace(/_/g, ' ').toLowerCase()))];
      findings.push({
        id: 'gsb-flagged', severity: 'critical', title: 'Flagged by Google Safe Browsing',
        detail: `Google's threat database lists this URL for: ${types.join(', ')}. Do not visit this link.`,
      });
      return { checked: true, flagged: true };
    }
    findings.push({
      id: 'gsb-clean', severity: 'info', title: 'Not in Google Safe Browsing blocklist',
      detail: "Google's threat database has no current record of this URL. New threats can take time to be listed.",
    });
    return { checked: true, flagged: false };
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------- */
/* Scoring + entry point                                             */
/* ---------------------------------------------------------------- */

function scoreFindings(findings) {
  let score = 0;
  for (const f of findings) score += SEVERITY_WEIGHT[f.severity] || 0;
  score = Math.min(100, score);
  let verdict = 'safe';
  if (score >= 60) verdict = 'dangerous';
  else if (score >= 25) verdict = 'caution';
  return { score, verdict };
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

async function scanUrl(rawInput) {
  const started = Date.now();
  const findings = [];

  const normalized = normalizeInput(rawInput);
  let url;
  try {
    url = new URL(normalized);
  } catch {
    throw inputError('That does not look like a valid URL. Example: https://example.com/page');
  }
  if (!['http:', 'https:', 'javascript:', 'data:', 'vbscript:'].includes(url.protocol)) {
    throw inputError(`Unsupported scheme "${url.protocol}" — Linkaware scans web links (http/https).`);
  }

  staticChecks(url, findings);

  let network = { chain: [{ url: url.href, status: null }], finalUrl: url.href, reachable: false };
  let ageInfo = null;
  let certInfo = null;
  let pageInfo = null;
  let hostingInfo = null;
  let gsbResult = null;
  let urlhausResult = null;

  const isWeb = url.protocol === 'http:' || url.protocol === 'https:';
  if (isWeb) {
    [network, ageInfo, certInfo, hostingInfo] = await Promise.all([
      followRedirects(url, findings),
      domainAge(url.hostname, findings),
      url.protocol === 'https:'
        ? tlsCheck(url.hostname, url.port ? Number(url.port) : 443, findings)
        : Promise.resolve(null),
      dnsAndHosting(url.hostname, findings),
    ]);

    // Re-run static analysis on the true destination if redirects moved us.
    const finalUrlObj = new URL(network.finalUrl);
    if (registrableDomain(finalUrlObj.hostname) !== registrableDomain(url.hostname)) {
      const destFindings = [];
      staticChecks(finalUrlObj, destFindings);
      const hasDowngrade = findings.some((x) => x.id === 'downgrade');
      for (const f of destFindings) {
        if (f.severity === 'info') continue;
        if (findings.some((x) => x.id === f.id)) continue;
        // The downgrade finding already penalizes an unencrypted destination.
        if (f.id === 'no-https' && hasDowngrade) continue;
        f.title = `Destination: ${f.title}`;
        findings.push(f);
      }
    }

    const [gsb, content, urlhaus] = await Promise.all([
      googleSafeBrowsing([url.href, network.finalUrl], findings),
      network.reachable ? contentChecks(network.finalUrl, findings) : Promise.resolve(null),
      urlhausLookup(url.hostname, findings),
    ]);
    pageInfo = content;
    gsbResult = gsb;
    urlhausResult = urlhaus;
  }

  // Reputation summary across every threat source we consulted.
  const reputation = { sources: [], flaggedBy: [] };
  if (gsbResult) {
    reputation.sources.push('Google Safe Browsing');
    if (gsbResult.flagged) reputation.flaggedBy.push('Google Safe Browsing');
  }
  if (urlhausResult) {
    reputation.sources.push('URLhaus (abuse.ch)');
    if (urlhausResult.flagged) reputation.flaggedBy.push('URLhaus (abuse.ch)');
  }

  // Visual preview via WordPress mShots (renders off-site, free, no key).
  const screenshotUrl = isWeb
    ? `https://s.wordpress.com/mshots/v1/${encodeURIComponent(network.finalUrl)}?w=1024`
    : null;

  const { score, verdict } = scoreFindings(findings);
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  if (!findings.some((f) => f.severity !== 'info')) {
    findings.push({
      id: 'no-issues', severity: 'info', title: 'No risk indicators detected',
      detail: 'None of our structural, network, or domain-intelligence checks raised a flag. Stay alert for anything a scanner cannot see, like page content asking for credentials.',
    });
  }

  return {
    input: rawInput,
    url: url.href,
    finalUrl: network.finalUrl,
    reachable: network.reachable,
    redirectChain: network.chain,
    domain: isIpHost(url.hostname) ? url.hostname : registrableDomain(url.hostname),
    domainInfo: ageInfo,
    certificate: certInfo,
    pageTitle: pageInfo?.title || null,
    hosting: hostingInfo,
    securityHeaders: pageInfo?.securityHeaders || null,
    technology: pageInfo?.technology || null,
    reputation: reputation.sources.length ? reputation : null,
    screenshotUrl,
    verdict,
    score,
    findings,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
  };
}

module.exports = {
  scanUrl,
  // exported for unit tests
  _internal: {
    registrableDomain, isIpHost, normalizeInput, editDistance, staticChecks, scoreFindings,
    gradeSecurityHeaders, fingerprintTechnology, isPrivateIp,
  },
};
