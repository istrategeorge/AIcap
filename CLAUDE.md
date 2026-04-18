# AIcap — Claude Code Context

## What this project is
**AIcap** — Continuous AI-BOM & Compliance Scanner for the EU AI Act.
- Go 1.23 backend + Supabase PostgreSQL + Stripe billing
- React/Vite frontend (single-page, no router)
- Deployed on Render (backend) + Vercel or Render (frontend)
- GitHub Action (`istrategeorge/AIcap@v1.0.0-beta`) runs the CLI scanner in CI pipelines

## Repo layout
```
main.go                        # entry point: HTTP server + --migrate subcommand
pkg/
  api/api.go                   # all HTTP handlers (RegisterRoutes)
  api/api_integration_test.go  # integration tests (build tag: integration)
  auth/auth.go                 # JWT + API key middleware, HashAPIKey
  httplog/httplog.go           # slog JSON handler + request-ID middleware
  migrate/                     # embedded SQL migration runner
  migrate/migrations/          # 00001..00009 SQL files
  scanner/                     # AI-BOM static analysis
  compliance/                  # EU AI Act compliance checks
  types/                       # shared types (AIBOM, ProofRecord, …)
frontend/src/App.jsx            # entire React frontend (single file)
docker-compose.yml              # local Postgres for integration tests
```

## Branching model
- `main` — stable / production
- `development` — active work branch (current: `d79d9fd`)
- All PRs target `development` first, then merge to `main` for release

## Tech stack versions
- Go module: `aicap` (`go.mod`)
- `lib/pq` — Postgres driver
- `stripe-go/v79` (v79.12.0)
- `golang-jwt/v5`
- React 18 + Vite + Tailwind + lucide-react

## Authentication model (Wave 3b — current)
Two distinct auth schemes, each for a different caller:

| Caller | Scheme | Routes |
|--------|--------|--------|
| Browser (dashboard) | Supabase session JWT (`RequireSupabaseJWT`) | `/api/history`, `/api/proof`, `/api/create-checkout-session`, `/api/generate-key`, `/api/rotate-key`, `/api/verify-checkout`, `/api/me` |
| CI pipeline | API key hash (`RequireAPIKey`) | `/api/save-proof` |

**API keys are hashed at rest** (SHA-256, column `token_hash`). The plaintext is returned exactly once from `/api/generate-key` or `/api/rotate-key` and never stored. `HashAPIKey(raw)` in `pkg/auth` is the canonical hash function.

## Database schema (migrations 00001–00009)
```
api_keys:       id, user_id (UNIQUE), token_hash, stripe_customer_id,
                subscription_tier, scans_this_month, created_at
proof_drills:   id, project_id, commit_sha, ai_bom_json, risk_register_state,
                annex_iv_markdown, crypto_hash, user_id (NOT NULL), created_at
projects:       id, name (UNIQUE), repository_url, created_at
stripe_events:  event_id (PK), event_type, received_at   ← idempotency table
schema_migrations: filename, applied_at
```
Key constraints: `api_keys.user_id` is UNIQUE (one key per user).
`proof_drills.user_id` is NOT NULL (Wave 3b removed the NULL bridge).

## Running locally
```bash
# Unit tests (no Docker needed)
go test ./...

# Integration tests (requires Docker)
docker compose up -d db
TEST_DATABASE_URL='postgres://aicap:aicap@localhost:5432/aicap?sslmode=disable' \
  go test -tags=integration ./...
docker compose down

# Run server locally (no DB)
go run main.go

# Run server with DB + migrations
SUPABASE_DB_URL='...' RUN_MIGRATIONS=true go run main.go

# Frontend dev server
cd frontend && npm run dev
```

## Environment variables
```
SUPABASE_DB_URL         Postgres connection string (enables cloud/SaaS mode)
SUPABASE_JWT_SECRET     HS256 secret for verifying Supabase session tokens
STRIPE_SECRET_KEY       Stripe API key
STRIPE_WEBHOOK_SECRET   Stripe webhook signing secret
STRIPE_PRICE_ID         Stripe price ID (default: price_1Pdtg1E5iL2Zl43n5G4YhI9t)
VITE_FRONTEND_URL       Allowed CORS origin(s), comma-separated
RUN_MIGRATIONS          Set to "true" to auto-run migrations on startup
LOG_LEVEL               "debug" for verbose slog output (default: info)
PORT                    HTTP port (default: 8080)
```

## Completed hardening waves
### Wave 1 (merged to main)
- CORS preflight fix (OPTIONS passes through auth middleware)
- Tenant scoping on `/api/history` and `/api/proof` (user_id isolation)
- Rate limiting: rolling 30-day window via composite index (free tier: 10 scans)

### Wave 2 (merged to main — commit e9aeb44)
- Embedded SQL migration runner (`pkg/migrate`) with idempotency
- Docker multi-stage build + `docker-compose.yml` for local Postgres
- Integration test suite behind `//go:build integration`
- `scans_this_month` replaced by rolling-window COUNT query

### Wave 3a (on development — commit 81b872c)
- Stripe webhook replay protection: `stripe_events` table (PK idempotency)
- Structured logging: `pkg/httplog` with JSON slog + per-request `X-Request-ID`
- Graceful shutdown: `*http.Server` with SIGTERM → 25s drain
- Error hygiene: raw DB/Stripe error strings scrubbed from HTTP responses

### Wave 3b (on development — commit 4ee14a4)
- `/api/history` and `/api/proof` switched to `RequireSupabaseJWT`
- `OR user_id IS NULL` tenant bridge removed; `proof_drills.user_id` NOT NULL
- `api_keys.token` dropped; SHA-256 hash stored in `token_hash`
- `/api/generate-key`: one-time reveal (201 once, then 409)
- `/api/rotate-key`: revokes current hash, issues new plaintext once
- Stripe webhook: upserts Pro tier marker (NULL token_hash); frontend materialises key
- Frontend: session shape is `{user, accessToken, hasKey, tier}` — no raw key in state

### Wave 3c (on development — checkout flow hardening + RLS-independent reads)
Commits: `f59e339`, `a2adeac`, `dd5d41f`, `ca9ff46`, `d79d9fd` — all on `development`.

- **Checkout return race fixed**: `onAuthStateChange` was double-firing
  `INITIAL_SESSION` + `TOKEN_REFRESHED`, causing two concurrent `/api/generate-key`
  calls on the checkout-return URL (one 201, one 409). Fixed by removing the
  separate `supabase.auth.getSession()` call and guarding `fetchAndSetUserSession`
  with a `useRef(false)` latch.
- **Checkout processing UI**: `checkoutProcessing` state is initialised from the
  `session_id` URL param so the spinner shows immediately on page load, before
  auth state fires. Render order checks `checkoutProcessing` BEFORE `!session`
  so users don't flash the login screen between Stripe redirect and session mount.
- **Webhook-independent verification**: new `GET /api/verify-checkout?session_id=…`
  endpoint calls Stripe's API directly (`session.Get`), confirms
  `Status == complete` (NOT `PaymentStatus == paid` — for `mode=subscription`
  that can be `unpaid`/`no_payment_required` when the event fires), and upserts
  Pro tier. This is the fallback when the Stripe webhook is misconfigured,
  delayed, or simply not yet set up on a staging environment.
- **Checkout-return fallback chain** (in `fetchAndSetUserSession`):
  1. Call `/api/generate-key` to materialise the key (idempotent via 409).
  2. Poll `/api/me` 3 × 1.5 s for `tier == 'pro'` (normal webhook path).
  3. If still not Pro, call `/api/verify-checkout` (Stripe API fallback).
- **`/api/me` endpoint**: returns `{hasKey, tier}` via the direct DB connection,
  bypassing Supabase RLS. Frontend no longer reads `api_keys` through the
  Supabase JS client, so session correctness does not depend on RLS policies
  being configured in the Supabase dashboard. RLS stays enabled as
  defense-in-depth (if the anon key leaks, it still blocks cross-tenant reads).

### Wave 4 (in progress — on development)
- **CI integration-test job** — `.github/workflows/go-test.yml` runs `go build`,
  `go test ./...` (unit) and `go test -tags=integration ./...` (integration,
  against a Postgres 16 service container) on every push/PR to `main` and
  `development`. Uses `go-version-file: go.mod` so the toolchain stays in sync
  with the module declaration instead of pinning a version that drifts.
- **`/livez` vs `/readyz` split** — `/livez` always returns 200 if the process
  can serve (for liveness probes: a failing DB must not trigger a pod
  restart). `/readyz` returns 503 when the DB ping fails so the orchestrator
  pulls the pod out of the LB. `/healthz` is kept as an alias of `/readyz`
  so existing Render probes don't break during a rolling probe-URL update.

## Pending work (Wave 4 remainder)
These items were explicitly deferred and not yet started:

1. **Merkle-tree ledger anchoring** — tamper-evidence for `proof_drills` rows using
   a hash-chain so a DB admin can't silently edit historical records
2. **Frontend refresh-token handling** — Supabase JWTs expire; the frontend currently
   has no `supabase.auth.onAuthStateChange` recovery path when a JWT expires
   mid-session (user sees silent 401s on dashboard calls)

## Wave 3b/3c deployment checklist (run before merging to main)
- [ ] RLS can stay as-is after Wave 3c — the frontend no longer reads `api_keys`
      directly, so `auth.uid() = user_id` row policies are sufficient as a
      defense-in-depth layer. A missing SELECT policy would no longer break the UI.
- [ ] Deploy with `RUN_MIGRATIONS=true` so 00008 + 00009 run against prod Supabase
- [ ] Confirm `ALTER TABLE api_keys DROP COLUMN token` succeeded (migration 00009)
- [ ] Test end-to-end: fresh signup → Stripe checkout → lands on Pro screen with
      key revealed → refresh page → still on Pro screen (not paywall)
- [ ] Test webhook fallback: with `STRIPE_WEBHOOK_SECRET` unset or the webhook
      disabled, complete checkout → `/api/verify-checkout` should still upgrade
      the user within ~7 s (Step 3 of the fallback chain)

## Key design decisions (do not re-litigate without good reason)
- **One key per user** enforced by `UNIQUE(user_id)` on `api_keys` — not application logic
- **No dual-auth bridge** on dashboard routes — there are no active users so no
  migration window was needed; API keys are simply rejected at `/api/history` and `/api/proof`
- **Stripe webhook does NOT materialise a raw key** — it upserts tier, frontend generates key
- **Frontend never reads `api_keys` directly via Supabase JS client** (post-Wave-3c) —
  all session state goes through `/api/me`. RLS remains as defense-in-depth, but
  application correctness does not depend on its configuration.
- **Checkout completion uses `Status == complete`, not `PaymentStatus == paid`** —
  for `mode=subscription`, Stripe fires `checkout.session.completed` before the
  first invoice payment settles, so `PaymentStatus` can be `unpaid` or
  `no_payment_required` even on a successful checkout.
- **`log/slog` for all structured logging**, not `log.Printf` — request-scoped logger
  via `httplog.From(r.Context())`, global logger via `slog.Default()`
- **`sha256.Sum256([]byte(key))` + `hex.EncodeToString`** is the canonical hash —
  matches Postgres `encode(sha256(convert_to(token, 'UTF8')), 'hex')`

## Notes on the test suite
- Unit tests: `go test ./...` — no DB, no Docker, runs everywhere
- Integration tests: `go test -tags=integration ./...` — requires `TEST_DATABASE_URL`
- `setup(t)` in `api_integration_test.go` applies all migrations + truncates tables
- `seedAPIKey` inserts a hashed key (post-Wave-3b); returns plaintext for headers
- `mintJWT` generates a test HS256 JWT using `jwtSecret = "integration-test-secret-do-not-use-in-prod"`
- Stripe webhook tests use `webhook.GenerateTestSignedPayload` with a local secret;
  event payloads must include `"api_version": "2024-06-20"` or `ConstructEvent` rejects them
