# PayPal Failure Doctor

An AI-assisted payment reliability workbench for PayPal integrations. Reproduce selected checkout failures, inspect traces, get a focused diagnosis, and view activity as it arrives.

## Stack and architecture

- **Frontend:** React + Vite. Production assets are served from Render Static Sites' global CDN.
- **API:** Node.js 24 + Express. Handles accounts, workspaces, diagnosis, workspace-scoped reliability metrics, PayPal Sandbox Orders v2, and Server-Sent Events.
- **Database:** PostgreSQL with parameterized queries, schema migrations, workspace-scoped records, indexes, and connection pooling.
- **Authentication:** Email/password accounts, versioned scrypt password hashes with lazy upgrades, opaque random session cookies (`HttpOnly`, `Secure` in production), expiring server-side sessions, workspace isolation, and optional authenticator-based two-step verification with one-use recovery codes. TOTP secrets are encrypted at rest with a server-only key.
- **Account controls:** Profile settings persist workspace renames. Signed-in users can change passwords after verifying the current password; the API revokes their other active sessions.
- **Operations:** Settings report application version, Node runtime, environment, uptime, and server time. Networking runs browser-side API latency and authenticated SSE connection checks.
- **Encryption:** The Encryption module can export the current run and advisor summary as a redacted `.fdx` incident bundle, encrypted in the browser with AES-256-GCM and a PBKDF2-SHA256-derived key. The passphrase is never sent to the server; this protects the exported file, not database records.
- **AI:** Anthropic Claude through the Vercel AI SDK. The AI receives the chosen scenario, trace, and sample code. It cannot create or capture a payment. The **Try local advisor** action uses deterministic rules bundled in the React app, so it works without an API key or network request after the app has loaded. Claude-powered analysis still requires the API server and a valid key.
- **AI diagnostics:** The Settings panel distinguishes a configured key from a verified Claude connection. **Check Claude connection** sends one small, rate-limited server-side request; diagnosis requests have a 20-second total timeout and fall back to the local advisor with a specific key, model, billing, rate-limit, or network message.
- **Payments:** PayPal JavaScript SDK v6 and Orders v2 use a server-selected environment. Sandbox remains the default. Live checkout is gated behind production runtime, PostgreSQL, distinct Live credentials and webhook, explicit enablement, and a server-configured product price and description. Failure injection is Sandbox-only.
- **Infrastructure:** Node-only local MVP for a quick start; optional Docker Compose for local PostgreSQL; Render Blueprint for HTTPS hosting and managed PostgreSQL.
- **Security:** Helmet headers and CSP, exact-origin CORS, origin checks on mutations, JSON payload limits, API and login rate limits, environment-based secrets, and a private database allow list.

```mermaid
flowchart LR
  Browser[Browser] -->|HTTPS assets| CDN[Render Static Site CDN]
  Browser -->|HTTPS API + SSE, credentials| API[Express API]
  API -->|Private network, parameterized SQL| DB[(Render PostgreSQL)]
  API -->|Sandbox Orders v2| PayPal[PayPal Sandbox]
  API -->|Scenario + trace| Claude[Anthropic Claude]
  DB -.->|PITR and snapshots on paid plan| Backup[Render recovery]
  DB -.->|Optional scheduled pg_dump| S3[Private S3 bucket]
```

## Run the MVP locally

Requires Node.js 22 or newer. Docker Desktop is optional. Create `.env` from `.env.example` only if you do not already have one; keep existing credentials and never overwrite your `.env` with the example file.

```powershell
npm ci
npm start
```

Open `http://localhost:8787` and create the first workspace account. Without `DATABASE_URL`, development mode uses a single-server file store in `server/data`: account passwords are versioned scrypt-hashed, session tokens are SHA-256 hashes, and activity is scoped to the signed-in workspace. This mode is for a single app process; use PostgreSQL for hosted production or multiple instances.

To try the app from a phone or tablet on the same Wi-Fi, open `http://<PC-LAN-IP>:8787` and allow Node through Windows Firewall if prompted. Local HTTP is for sandbox/demo use only; use the HTTPS Render URL for access over the public internet.

For PostgreSQL-backed local development, install Docker Desktop, set `DATABASE_URL=postgresql://failuredoctor:localdev@localhost:5432/failuredoctor` in `.env`, then run:

```powershell
docker compose up -d postgres
npm run db:migrate
npm start
```

Or run the built app and database together at `http://localhost:8787` with `docker compose up --build`. Compose runs migrations before app startup. `docker compose down` stops services; `docker compose down -v` deletes the local database volume.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Optional in local development; enables PostgreSQL-backed accounts and durable shared activity. Required in production. |
| `LOCAL_AUTH_ENABLED` | Local-only file authentication toggle; enabled by default in development. |
| `MFA_ENCRYPTION_KEY` | Stable base64-encoded 32-byte API-server key used to encrypt authenticator secrets and HMAC recovery codes. Required to enroll MFA; back it up securely and never commit it. |
| `ALLOWED_ORIGINS` | Comma-separated exact browser origins allowed to call the API. |
| `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` | PayPal Sandbox REST app credentials. Keep the Secret on the server. |
| `PAYPAL_ENVIRONMENT` | `sandbox` by default. Set to `live` only on a `NODE_ENV=production` server. |
| `PAYPAL_SANDBOX_CLIENT_ID` / `PAYPAL_SANDBOX_CLIENT_SECRET` | Explicitly scoped Sandbox credentials; legacy `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` remain Sandbox-only aliases. |
| `PAYPAL_CURRENCY` | Sandbox checkout currency; defaults to USD. |
| `PAYPAL_WEBHOOK_ID` | Optional ID of the Sandbox webhook registered to your public `/api/paypal/webhooks` URL. |
| `PAYPAL_SANDBOX_WEBHOOK_ID` | Explicitly scoped Sandbox webhook ID; legacy `PAYPAL_WEBHOOK_ID` remains a Sandbox-only alias. |
| `PAYPAL_LIVE_PAYMENTS_ENABLED` | Must be exactly `true` to unlock Live checkout; defaults to `false`. |
| `PAYPAL_LIVE_CLIENT_ID` / `PAYPAL_LIVE_CLIENT_SECRET` | Live REST app credentials. Keep the Secret server-side and separate from Sandbox credentials. |
| `PAYPAL_LIVE_WEBHOOK_ID` | Webhook ID from the matching Live PayPal app. |
| `PAYPAL_LIVE_AMOUNT` / `PAYPAL_LIVE_CURRENCY` / `PAYPAL_LIVE_DESCRIPTION` | Required server-side checkout product configuration. No Live amount or product is assumed by the app. |
| `ANTHROPIC_API_KEY` | Optional key for Claude-powered diagnosis. |
| `CLAUDE_MODEL` | Claude model name configured for the API; defaults to `claude-sonnet-5-5`. |
| `PG_POOL_MAX` | PostgreSQL connection pool size (default 10). |
| `PGSSLMODE` | Set to `require` only when your remote database connection requires TLS. |

## Two-step sign-in

Sign in, open **Authentication**, and set up an authenticator app. The app uses six-digit, 30-second TOTP codes. Enrollment requires the current account password and an authenticator code; sign-in then requires both the password and a current code. Ten one-use recovery codes are displayed once after enrollment. Store them in a password manager. Login challenges expire after five minutes and allow at most five code attempts; accepted authenticator time steps cannot be replayed.

Set `MFA_ENCRYPTION_KEY` on the API server before enrollment. Generate a key once with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`. Keep the same key across restarts and deployments, back it up in a secrets manager, and do not add it to Git or a browser variable. Losing or changing this key can prevent enrolled users from signing in. Existing database installations must run `npm run db:migrate` before using MFA; Render runs the migration during deploy. This adds a second sign-in factor, but TOTP can still be phished and does not protect a stolen active session; it is not a guarantee that an account cannot be compromised.

## Database and data isolation

`server/schema.sql` creates users, workspaces, memberships, expiring sessions, payment activity records, and a deduplicated PayPal webhook ledger. Run `npm run db:migrate` after configuring `DATABASE_URL`. Every displayed activity query is scoped to the authenticated session's workspace. Passwords are never stored in plaintext; session tokens are stored as SHA-256 hashes. The ledger stores a redacted event summary, order/resource IDs, status, and delivery counts, not full buyer/payment response bodies.

### PayPal Sandbox webhook setup

1. Deploy the app to an HTTPS URL that PayPal can reach. Set the webhook URL to `https://<your-api-host>/api/paypal/webhooks` in the same PayPal Sandbox app as the client credentials.
2. Subscribe to checkout/order and payment/capture events that you want to inspect (for example, `CHECKOUT.ORDER.APPROVED`, `CHECKOUT.ORDER.COMPLETED`, `PAYMENT.CAPTURE.COMPLETED`, and `PAYMENT.CAPTURE.DENIED`).
3. Copy that webhook's ID into the API server as `PAYPAL_WEBHOOK_ID`. The server verifies each signature by calling PayPal's official Sandbox verification endpoint before storing a minimal summary.
4. Open **Test runs → PayPal webhook reconciliation**. Deliveries linked to an order created in that workspace appear there; repeated PayPal delivery IDs increment the count and do not create a second activity record.

This route is unavailable until the client ID, client secret, and webhook ID are configured. A local `localhost` URL cannot receive PayPal's internet webhook calls. For local-only route tests, use PayPal's webhook simulator or a secure tunnel and keep it in Sandbox.

## Deploy on Render

The root `render.yaml` defines a Singapore-region Node API, a managed PostgreSQL database reachable only over Render's private network, and a static React site distributed through Render's CDN. The database uses a paid plan so managed point-in-time recovery is available. These cloud resources can incur ongoing charges; review the selected plans and pricing before creating the Blueprint.

1. Push this repository to a public or private GitHub repository.
2. For the MVP, open the API web service's root URL: Express serves the built app from the same origin, so secure sign-in works with the default Render URL. To use the separate static CDN frontend, add custom domains under the same parent domain, such as `app.example.com` and `api.example.com`; the default Render subdomains are separate sites and are unreliable for cross-site session cookies.
3. In Render, create a Blueprint from that repository and review every resource and plan before applying it. At setup, set `VITE_API_BASE_URL` to the API custom domain and `ALLOWED_ORIGINS` to the comma-separated browser origins you will use (the frontend custom domain, and the API domain too if you plan to open its same-origin app). Also update the frontend Content-Security-Policy `connect-src` with the API custom domain.
4. The Blueprint sets `PAYPAL_ENVIRONMENT=sandbox` and `PAYPAL_LIVE_PAYMENTS_ENABLED=false`. Add Sandbox credentials and the optional Sandbox webhook ID, plus `ANTHROPIC_API_KEY`, in the Render Dashboard; never put secrets in `render.yaml` or Git. Sandbox remains fictional-money testing even though the app server runs in production mode.
5. The API runs `npm run db:migrate` as its pre-deploy command. The static site build receives `VITE_API_BASE_URL` and serves assets through Render's CDN.
6. Register a workspace account on the deployed site. Use PayPal Sandbox buyer credentials for checkout tests.

### Deliberately enabling Live checkout

Live checkout is a separate, server-controlled deployment mode. Do not turn it on for the hackathon demo or on a developer workstation. First deploy a separate production API and PostgreSQL database for Live traffic; keep the Sandbox/simulator deployment and its database separate. A database-level environment lock refuses to start a Sandbox API against a Live database (or vice versa), so the two deployments cannot silently share payment history. Then, in the Live API service's secret settings, set `PAYPAL_ENVIRONMENT=live`, configure `PAYPAL_LIVE_CLIENT_ID`, `PAYPAL_LIVE_CLIENT_SECRET`, `PAYPAL_LIVE_WEBHOOK_ID`, `PAYPAL_LIVE_AMOUNT`, `PAYPAL_LIVE_CURRENCY`, and a buyer-accurate `PAYPAL_LIVE_DESCRIPTION`, and only after review set `PAYPAL_LIVE_PAYMENTS_ENABLED=true`. The app refuses Live mode outside `NODE_ENV=production`, returns 503 until the full server-side gate is satisfied, uses PayPal's Live API and SDK origins, and never sends the Sandbox mock-failure header or a Live payment trace to AI analysis.

Register the webhook URL with the same Live REST app as the Live credentials. Validate checkout, approval, cancellation, capture status, and webhook verification in a controlled merchant-owned launch before allowing buyers. The API records capture status but does not deliver a product or fulfill an order; integrate your real fulfillment and refund processes before using Live checkout commercially. See PayPal's [REST API base URLs](https://developer.paypal.com/api/make-api-requests/), [JavaScript SDK v6 setup](https://developer.paypal.com/sdk/js/set-up), [go-live checklist](https://developer.paypal.com/sdk/js/production), and [webhook verification guide](https://developer.paypal.com/api/rest/webhooks/rest/).

Render's Blueprint and platform docs: [Blueprint specification](https://render.com/docs/blueprint-spec), [private networking](https://render.com/docs/private-network), [environment variables](https://render.com/docs/configure-environment-variables), [static sites/CDN](https://render.com/docs/static-sites).

## CI/CD

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`. It installs the lockfile dependencies, runs the password/MFA/webhook unit tests, builds the frontend, checks server syntax, checks production dependencies for high/critical advisories, and builds the production Docker image. Render deploys commits from the connected branch. Protect `main` in GitHub and require the CI check before merge to make the build gate effective.

## Backups and recovery

The Render database plan in `render.yaml` is paid; Render provides point-in-time recovery for paid PostgreSQL databases. Current documented recovery windows vary by workspace plan: three days on Hobby and seven days on Pro or higher. A free Render database does not include recovery and expires after 30 days. Verify current retention in your Render dashboard before relying on it. See [Render Postgres recovery and backups](https://render.com/docs/postgresql-backups).

For a separate offsite logical backup, `scripts/backup-postgres.sh` uses `pg_dump` and uploads an encrypted custom-format dump to a private S3 bucket. `Dockerfile.backup` is the job image. To schedule it, append this service to the root `services:` list in `render.yaml`:

```yaml
  - type: cron
    name: failure-doctor-db-backup
    runtime: docker
    dockerfilePath: ./Dockerfile.backup
    region: singapore
    plan: 0.5c-512mb
    schedule: "0 2 * * *"
    envVars:
      - key: DATABASE_URL
        fromDatabase:
          name: failure-doctor-db
          property: connectionString
      - key: S3_BACKUP_BUCKET
        sync: false
      - key: AWS_ACCESS_KEY_ID
        sync: false
      - key: AWS_SECRET_ACCESS_KEY
        sync: false
      - key: AWS_DEFAULT_REGION
        sync: false
```

This job has separate compute and S3 costs. Set an S3 lifecycle policy for retention, enable bucket versioning if desired, block public access, and test restores with `pg_restore` into a separate database. Store AWS credentials with the narrowest bucket-only permissions.

Never treat a backup as verified until a restore has been tested. Keep a recovery runbook and a separate protected environment for restore drills.

## Security and operational notes

- Production session cookies use `Secure`, `HttpOnly`, and `SameSite=Lax`. The frontend and API must use HTTPS custom domains under the same parent domain. CORS is restricted to configured origins, and unsafe browser requests require an allowed `Origin`.
- The API rate-limits requests and more tightly limits sign-in attempts. Its current limiter uses per-process memory; before running multiple API instances, move rate-limit counters to a shared store. Database access is restricted to Render's private network in the Blueprint; use the internal database URL for the API.
- Keep secrets in local `.env` or the cloud provider's secret settings. Rotate any credential that was accidentally committed or shared.
- This is a hackathon foundation, not a security-audited payment product. Keep it in Sandbox until authentication, deployment settings, backup restore, and payment flows have been reviewed for the intended use.
- Do not use live PayPal credentials or live payment endpoints in this demo.

## Demo flow

1. Select a failure scenario and run it in the simulator, or choose **Run full suite** to execute an unsafe baseline and repaired path for every supported scenario.
2. Inspect the suite report, individual traces, checks, and AI/local diagnosis.
3. Compare the unsafe baseline with each repaired simulation. The full suite uses the local simulator and does not call PayPal or Claude.
4. Optionally create a $2 PayPal Sandbox order and approve it with a Sandbox buyer account; Sandbox uses fictional test funds and does not move real money. The API injects the selected negative-test response at capture, and the run passes only when PayPal returns that expected failure. Use the local simulator for a zero-payment demo.
5. Watch the live activity panel update and confirm history persists after an app restart.
6. On a public HTTPS deployment with a configured Sandbox webhook, inspect event linkage and duplicate delivery counts in the reconciliation panel.

## License

MIT. See [LICENSE](./LICENSE).
