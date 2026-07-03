# LinkSentry 🛡️

**Know before you click.** A complete, production-ready URL safety scanner — free public scanner, user accounts, dashboard, developer API, and Stripe-ready billing.

## Features

**Scan engine (18+ checks per scan)**
- Structural analysis: brand impersonation, typosquat detection (edit-distance vs 40 top domains), punycode look-alikes, `@`-credential tricks, high-abuse TLDs, credential-bait keywords, raw IP hosts, deceptive subdomains, odd ports, heavy encoding
- Live inspection: full redirect-chain tracing (shorteners unmasked), HTTPS downgrade detection, TLS certificate validation (expired / self-signed / issuer), direct-download detection
- Page content analysis: password-form detection, hidden meta-refresh redirects, page title capture
- Domain intelligence: registration age via public RDAP (free, no key needed)
- Optional threat feeds: Google Safe Browsing (set `GSB_API_KEY`)

**Product**
- Public scanner with animated risk gauge and plain-English findings
- Accounts (scrypt-hashed passwords, DB sessions), dashboard with scan history
- Shareable report permalinks (`/r/:id`) with JSON download and print-to-PDF
- Bulk scanning (5 URLs/batch free, 20 pro)
- Developer API (`POST /api/v1/scan`) with API keys, monthly quotas (100 free / 10,000 pro), quota headers, and a full docs page at `/docs`
- Stripe subscription billing — flips on automatically when env keys are set; graceful waitlist mode until then
- Rate limiting, security headers, privacy + terms pages, robots/sitemap, 404 page

## Run locally

```
cd linksentry
npm install
npm start        # http://localhost:3000
```

Run tests: `npm test`

## Configuration (all optional)

See [.env.example](.env.example). Highlights:

| Variable | Effect |
|---|---|
| `GSB_API_KEY` | Adds Google Safe Browsing blocklist checks (free key from Google Cloud console) |
| `STRIPE_SECRET_KEY` + `STRIPE_PRICE_ID` | Enables real Pro checkout ($9/mo). Create a recurring price in Stripe, paste the ids |
| `STRIPE_WEBHOOK_SECRET` | Verifies Stripe webhooks (`POST /api/billing/webhook`) so upgrades apply automatically |
| `PRO_EMAILS` | Comma-separated emails that get Pro free (put your own email here) |
| `APP_URL` | Public URL, used in Stripe redirects |
| `DATA_DIR` | SQLite location (default `./data`) |

## Deploying (make it public)

- **Render** — repo includes [render.yaml](render.yaml): push to GitHub, "New → Blueprint" on render.com, done. Persistent disk keeps the database.
- **Docker** — `docker build -t linksentry . && docker run -p 3000:3000 -v linksentry-data:/data linksentry`
- **Any VPS** — `node server.js` behind Caddy/nginx for HTTPS.

Then point your domain at it and update `APP_URL`, `robots.txt`, and `sitemap.xml` with the real domain.

## Launch checklist for monetization

1. Buy a domain (e.g. linksentry.app) and deploy.
2. Create a Stripe account → add a $9/mo recurring price → set the three `STRIPE_*` vars → the "Upgrade to Pro" button starts charging real money.
3. Add a webhook endpoint in Stripe pointing to `https://yourdomain/api/billing/webhook` (events: `checkout.session.completed`, `customer.subscription.deleted`).
4. Get a free `GSB_API_KEY` for stronger verdicts.
5. Replace `hello@linksentry.app` placeholders with your real contact email (privacy/terms pages).

## Project structure

```
linksentry/
├── server.js            # Express app: all routes, rate limiting
├── lib/
│   ├── scanner.js       # Scan engine
│   ├── db.js            # SQLite schema (users, sessions, api_keys, scans, usage)
│   ├── auth.js          # Passwords, sessions, middleware
│   ├── apikeys.js       # Key management + quotas
│   └── billing.js       # Stripe (REST via fetch, no SDK)
├── public/              # Frontend (landing, dashboard, docs, report, legal)
├── tests/               # node --test suite
├── Dockerfile, render.yaml, .env.example
```
