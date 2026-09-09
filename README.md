# Linkaware 🛡️

**Know before you click.** A free URL safety scanner — paste any link and get an instant risk verdict, with no account, no ads, and no paid tier.

## Features

**Scan engine (25+ checks per scan)**
- Structural analysis: brand impersonation, typosquat detection (edit-distance vs 40 top domains), punycode look-alikes, `@`-credential tricks, high-abuse TLDs, credential-bait keywords, raw IP hosts, deceptive subdomains, odd ports, heavy encoding
- Live inspection: full redirect-chain tracing (shorteners unmasked), HTTPS downgrade detection, TLS certificate validation (expired / self-signed / issuer), direct-download detection
- Page content analysis: password-form detection, hidden meta-refresh redirects, page title capture
- Hosting intelligence: IP, ASN, host organisation, country/city, DNS-rebinding and dead-domain checks
- Security-header grading (A–F) and technology fingerprinting
- Domain intelligence: registration age, registrar, nameservers and expiry via public RDAP
- Sandboxed visual preview of the destination page
- Threat feeds: Google Safe Browsing (set `GSB_API_KEY`), optional URLhaus

**Product**
- Public scanner with animated risk gauge and plain-English findings
- Optional accounts (scrypt-hashed passwords, DB sessions) with scan history
- Shareable report permalinks (`/r/:id`) with JSON download and print-to-PDF
- Bulk scanning, 25 URLs per batch
- Free developer API (`POST /api/v1/scan`) with API keys and a fair-use monthly cap
- Owner admin panel at `/admin` (users, totals, live scan feed)
- Rate limiting, security headers, privacy + terms pages, robots/sitemap, 404 page

## Free, permanently

There is no paid plan and no billing code in this project. The only limits are
anti-abuse guards so one client can't exhaust the shared upstream threat-feed
budget:

| Guard | Limit |
|---|---|
| Public scanner | 20 scans/min per IP |
| Bulk scanning | 25 URLs per batch (unlimited batches) |
| API | 1,000 scans/month per key |

## Run locally

```
cd linkaware
npm install
npm start        # http://localhost:3000
```

Run tests: `npm test`

## Configuration (all optional)

See [.env.example](.env.example).

| Variable | Effect |
|---|---|
| `GSB_API_KEY` | Adds Google Safe Browsing blocklist checks (free key from Google Cloud console) |
| `URLHAUS_API_KEY` | Adds abuse.ch malware-host reputation checks (free key) |
| `ADMIN_EMAILS` | Comma-separated emails allowed into `/admin` |
| `APP_URL` | Public base URL of the deployment |
| `DATA_DIR` | SQLite location (default `./data`) |

## Deploying

- **Render** — repo includes [render.yaml](render.yaml): push to GitHub, "New → Blueprint". Note the free plan has an **ephemeral disk**, so the database resets on restart; add a persistent disk (paid) to keep accounts.
- **Docker** — `docker build -t linkaware . && docker run -p 3000:3000 -v linkaware-data:/data linkaware`
- **Any VPS** — `node server.js` behind Caddy/nginx for HTTPS.

Set the same environment variables in your host's dashboard, since `.env` is never committed.

## Project structure

```
linkaware/
├── server.js            # Express app: all routes, rate limiting
├── lib/
│   ├── scanner.js       # Scan engine
│   ├── db.js            # SQLite schema (users, sessions, api_keys, scans, usage)
│   ├── auth.js          # Passwords, sessions, middleware
│   └── apikeys.js       # Key management + fair-use quota
├── public/              # Frontend (landing, dashboard, docs, report, admin, legal)
├── tests/               # node --test suite
├── Dockerfile, render.yaml, .env.example
```
