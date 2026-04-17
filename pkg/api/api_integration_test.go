//go:build integration

// Integration tests for pkg/api. Kept behind the `integration` build tag
// because they require a reachable Postgres. Run with:
//
//   TEST_DATABASE_URL=postgres://aicap:aicap@localhost:5432/aicap?sslmode=disable \
//     go test -tags=integration ./pkg/api/...
//
// `docker compose up -d db` from the repo root starts a matching database.
// The default `go test ./...` path ignores these so laptops without Docker
// still get a clean unit-test run.
package api_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"aicap/pkg/api"
	"aicap/pkg/migrate"
	"aicap/pkg/types"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"github.com/stripe/stripe-go/v79/webhook"
)

const jwtSecret = "integration-test-secret-do-not-use-in-prod"

// setup brings up a full backend against TEST_DATABASE_URL: applies
// migrations, clears any prior test data, returns the configured
// httptest.Server and db handle. Each test calls this to get an isolated
// environment — tests share the same schema but truncate their tables so
// they don't see each other's rows.
func setup(t *testing.T) (*httptest.Server, *sql.DB) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	if err := migrate.Apply(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Wipe every table this test suite touches. TRUNCATE … CASCADE handles
	// the FK between proof_drills and projects, and RESTART IDENTITY zeroes
	// any sequence so test assertions that depend on row counts are stable.
	if _, err := db.Exec(`TRUNCATE proof_drills, projects, api_keys, stripe_events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	t.Setenv("SUPABASE_JWT_SECRET", jwtSecret)
	t.Setenv("VITE_FRONTEND_URL", "https://app.example.com")
	// Pass isCloudSaaS=true so auth middleware is wired in, matching prod.
	mux := http.NewServeMux()
	api.RegisterRoutes(mux, db, true)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		db.Close()
	})
	return srv, db
}

func mintJWT(t *testing.T, sub, email string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":   sub,
		"email": email,
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// seedAPIKey inserts a Pro API key for `userID` and returns the raw token the
// CLI would present. After Wave 3b the database only stores the SHA-256 hash
// (column: token_hash) — we hash at seed time, then hand the plaintext back
// so the test can put it in an Authorization header. A deterministic token
// string per user_id keeps assertions stable across runs.
func seedAPIKey(t *testing.T, db *sql.DB, userID, tier string) string {
	t.Helper()
	token := fmt.Sprintf("aicap_pro_sk_test_%s", userID)
	sum := sha256.Sum256([]byte(token))
	hashed := hex.EncodeToString(sum[:])
	if _, err := db.Exec(
		`INSERT INTO api_keys (user_id, token_hash, subscription_tier) VALUES ($1, $2, $3)`,
		userID, hashed, tier,
	); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	return token
}

// TestHealthz_OK is the smoke test — if this fails, everything below is
// suspect (wiring, DB connectivity, migration runner, route registration).
func TestHealthz_OK(t *testing.T) {
	srv, _ := setup(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestCORSPreflight_NoAuthRejection is the regression test for the Wave 1
// CORS bug: the browser sends OPTIONS without Authorization, and earlier
// versions of the middleware returned 401, breaking every cross-origin call.
func TestCORSPreflight_NoAuthRejection(t *testing.T) {
	srv, _ := setup(t)
	for _, path := range []string{"/api/create-checkout-session", "/api/history", "/api/save-proof"} {
		req, _ := http.NewRequest(http.MethodOptions, srv.URL+path, nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("preflight %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("%s: preflight returned 401 — CORS will break", path)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "" {
			t.Errorf("%s: missing Access-Control-Allow-Origin on preflight", path)
		}
	}
}

// TestSaveProof_RequiresAPIKey proves the route is guarded — an unauthed
// POST gets 401, not a "thanks, saved!" for a phantom user.
func TestSaveProof_RequiresAPIKey(t *testing.T) {
	srv, _ := setup(t)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof",
		bytes.NewBufferString(`{"ProjectName":"demo","CommitSha":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestSaveProof_HappyPath covers the dominant Pro-CLI flow: valid API key
// in, row persisted with the authenticated user's ID attached.
func TestSaveProof_HappyPath(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000001"
	token := seedAPIKey(t, db, userID, "pro")

	body := types.AIBOM{ProjectName: "demo/repo", CommitSha: "deadbeef"}
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}

	// Verify the row landed with the right user_id — this is the
	// Wave 1 tenant-scoping contract.
	var gotUser string
	if err := db.QueryRow(
		`SELECT user_id::text FROM proof_drills WHERE commit_sha = $1`, "deadbeef",
	).Scan(&gotUser); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if gotUser != userID {
		t.Errorf("proof_drills.user_id = %q, want %q", gotUser, userID)
	}
}

// TestSaveProof_FreeTierQuota exercises the new rolling-window rate limit:
// the 10th scan in the last 30 days succeeds, the 11th returns 402.
func TestSaveProof_FreeTierQuota(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000002"
	token := seedAPIKey(t, db, userID, "free")

	post := func() int {
		b, _ := json.Marshal(types.AIBOM{ProjectName: "demo", CommitSha: "sha"})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 10; i++ {
		if got := post(); got != 201 {
			t.Fatalf("scan %d: status = %d, want 201", i+1, got)
		}
	}
	if got := post(); got != http.StatusPaymentRequired {
		t.Errorf("scan 11: status = %d, want 402", got)
	}
}

// TestHistory_TenantScoping is the "do not leak the ledger" guarantee: two
// users each save a proof via the CLI path (API key) and read their
// dashboard via the browser path (Supabase JWT). Each /api/history call
// must see only its own row.
//
// The route swap in Wave 3b is the relevant regression: /api/history moved
// from RequireAPIKey to RequireSupabaseJWT. If that swap broke tenant
// scoping we'd see Alice's JWT returning Bob's rows.
func TestHistory_TenantScoping(t *testing.T) {
	srv, db := setup(t)
	alice := "00000000-0000-0000-0000-000000000010"
	bob := "00000000-0000-0000-0000-000000000020"
	aliceAPIKey := seedAPIKey(t, db, alice, "pro")
	bobAPIKey := seedAPIKey(t, db, bob, "pro")

	// CI path (still uses API keys): each user pushes one scan.
	for _, p := range []struct{ tok, commit string }{
		{aliceAPIKey, "alice-sha"}, {bobAPIKey, "bob-sha"},
	} {
		b, _ := json.Marshal(types.AIBOM{ProjectName: "demo", CommitSha: p.commit})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/save-proof", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+p.tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("seed %s: %v", p.commit, err)
		}
		resp.Body.Close()
	}

	// Dashboard path (Wave 3b: Supabase JWT): Alice's history must contain
	// alice-sha and exactly one row.
	aliceJWT := mintJWT(t, alice, "alice@example.com")
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/history", nil)
	req.Header.Set("Authorization", "Bearer "+aliceJWT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	defer resp.Body.Close()
	var records []types.ProofRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("alice saw %d rows, want 1 — possible tenant leak", len(records))
	}
	if records[0].CommitSha != "alice-sha" {
		t.Errorf("alice saw commit %q, want alice-sha", records[0].CommitSha)
	}
}

// TestHistory_RejectsAPIKey is the explicit regression for Wave 3b's route
// swap: a caller presenting a valid API key (CLI credential) must now be
// rejected at the dashboard endpoint. This prevents accidental regression
// back to the old model that stored raw keys in the browser.
func TestHistory_RejectsAPIKey(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-0000000000a1"
	apiKey := seedAPIKey(t, db, userID, "pro")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/history", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/history: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (API key must not authenticate dashboard routes)", resp.StatusCode)
	}
}

// TestGenerateKey_OneTimeReveal covers the Wave 3b one-time-reveal contract:
//   - First call: 201 with a plaintext aicap_pro_sk_* key in the response body.
//   - Second call (no rotation): 409 because the raw key is unrecoverable
//     and we must not silently re-issue.
//   - /api/rotate-key produces a *different* plaintext and leaves the DB
//     with exactly one row for the user (UNIQUE(user_id) enforcement).
//
// The regression we're blocking: any path that returns a raw key by reading
// it from the database. After migration 00009 the plaintext column is gone,
// so such a path would have to materialise a new key every call — which is
// exactly the silent-double-provision bug Wave 3b closed.
func TestGenerateKey_OneTimeReveal(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-0000000000b2"
	tok := mintJWT(t, userID, "b@example.com")

	call := func(path string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		var body struct{ APIKey string `json:"apiKey"` }
		json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body.APIKey
	}

	status, firstKey := call("/api/generate-key")
	if status != http.StatusCreated {
		t.Fatalf("first generate-key status = %d, want 201", status)
	}
	if firstKey == "" {
		t.Fatal("first generate-key returned empty apiKey")
	}

	// Second call must refuse to re-issue — the raw key is gone from the
	// server's point of view.
	status, _ = call("/api/generate-key")
	if status != http.StatusConflict {
		t.Errorf("second generate-key status = %d, want 409", status)
	}

	// Rotation must produce a different plaintext.
	status, rotatedKey := call("/api/rotate-key")
	if status != http.StatusOK {
		t.Fatalf("rotate-key status = %d, want 200", status)
	}
	if rotatedKey == firstKey {
		t.Error("rotate-key returned the original key — rotation is a no-op")
	}

	// And the user still has exactly one row (UNIQUE(user_id) held).
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("api_keys rows for user = %d, want 1", rows)
	}
}

// TestGenerateKey_AfterCheckoutWebhook covers the handoff between the
// Stripe webhook and the frontend's post-redirect generate-key call.
// The webhook creates a Pro-tier row with NULL token_hash; the subsequent
// generate-key call must materialise the hash and preserve the 'pro' tier
// (not silently downgrade the user).
func TestGenerateKey_AfterCheckoutWebhook(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-0000000000b3"

	// Simulate the webhook's effect directly — this test is about the
	// generate-key handoff, not the webhook signature path.
	if _, err := db.Exec(
		`INSERT INTO api_keys (user_id, stripe_customer_id, subscription_tier)
		 VALUES ($1, 'cus_test_handoff', 'pro')`, userID,
	); err != nil {
		t.Fatalf("simulate webhook upsert: %v", err)
	}

	tok := mintJWT(t, userID, "handoff@example.com")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/generate-key", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("generate-key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	// Tier must still be 'pro' — the generate-key UPSERT must not clobber
	// the subscription_tier the webhook recorded.
	var tier string
	if err := db.QueryRow(
		`SELECT subscription_tier FROM api_keys WHERE user_id = $1`, userID,
	).Scan(&tier); err != nil {
		t.Fatalf("read tier: %v", err)
	}
	if tier != "pro" {
		t.Errorf("tier after generate-key = %q, want pro (silent downgrade!)", tier)
	}
}

// TestCheckoutSession_RequiresValidJWT — a missing or bogus Supabase token
// must not reach the Stripe call. We don't verify the Stripe side here; we
// just assert the gate held.
func TestCheckoutSession_RequiresValidJWT(t *testing.T) {
	srv, _ := setup(t)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/create-checkout-session",
		bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not.a.real.jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestGenerateKey_DerivesUserFromJWT — the endpoint must never trust a
// user_id in the request body. We only present a JWT; the key that gets
// issued must belong to the JWT's sub claim.
func TestGenerateKey_DerivesUserFromJWT(t *testing.T) {
	srv, db := setup(t)
	userID := "00000000-0000-0000-0000-000000000099"
	tok := mintJWT(t, userID, "u@example.com")

	// Body carries a *different* user_id. If the handler honours it we fail.
	body := `{"userID":"00000000-0000-0000-0000-0000000000ff"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/generate-key",
		bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 2xx", resp.StatusCode)
	}

	// The DB row must be attributed to the JWT sub, not the body claim.
	var storedUser string
	if err := db.QueryRow(
		`SELECT user_id::text FROM api_keys WHERE user_id = $1`, userID,
	).Scan(&storedUser); err != nil {
		t.Fatalf("lookup: %v (tenant confusion possible)", err)
	}
	if storedUser != userID {
		t.Errorf("api_keys.user_id = %q, want %q", storedUser, userID)
	}
}

// TestStripeWebhook_IdempotencyReplay is the contract for Wave 3's replay
// protection: Stripe delivers each event at least once, so our handler must
// treat a second delivery of the same event_id as a no-op.
//
// We drive this end-to-end through the real webhook endpoint (signature
// verification and all) rather than unit-testing the INSERT logic directly,
// because the bug we're defending against is the whole pipeline double-firing.
// A `checkout.session.completed` event is used because it has an observable
// side effect (inserts an api_keys row) — the assertion "one row after two
// deliveries" would fail loudly if the guard ever regresses.
func TestStripeWebhook_IdempotencyReplay(t *testing.T) {
	const webhookSecret = "whsec_integration_test"
	t.Setenv("STRIPE_WEBHOOK_SECRET", webhookSecret)
	srv, db := setup(t)

	userID := "00000000-0000-0000-0000-0000000000aa"
	eventID := "evt_test_idem_replay_1"

	// Minimal but valid Stripe event JSON. The handler extracts user_id from
	// metadata and customer from cs.Customer; everything else is decoration.
	// api_version must match what the installed stripe-go library expects or
	// ConstructEvent rejects the payload before it ever reaches our handler.
	payload := []byte(fmt.Sprintf(`{
		"id": %q,
		"object": "event",
		"api_version": "2024-06-20",
		"type": "checkout.session.completed",
		"data": {
			"object": {
				"id": "cs_test_idem_1",
				"object": "checkout.session",
				"customer": "cus_test_idem_1",
				"metadata": {"user_id": %q}
			}
		}
	}`, eventID, userID))

	send := func() int {
		signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{
			Payload: payload,
			Secret:  webhookSecret,
		})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/stripe-webhook", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Stripe-Signature", signed.Header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post webhook: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// First delivery: expect the full provision flow to run.
	if code := send(); code != http.StatusOK {
		t.Fatalf("first delivery status = %d, want 200", code)
	}
	var apiKeysAfter1 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&apiKeysAfter1); err != nil {
		t.Fatalf("count api_keys: %v", err)
	}
	if apiKeysAfter1 != 1 {
		t.Fatalf("after first delivery: api_keys rows = %d, want 1 (side effect didn't run)", apiKeysAfter1)
	}

	// Second delivery: same event_id. The guard must short-circuit before
	// any side effect runs, so api_keys stays at exactly one row.
	if code := send(); code != http.StatusOK {
		t.Fatalf("second delivery status = %d, want 200 (idempotency should still acknowledge)", code)
	}
	var apiKeysAfter2 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&apiKeysAfter2); err != nil {
		t.Fatalf("count api_keys after replay: %v", err)
	}
	if apiKeysAfter2 != 1 {
		t.Errorf("after replay: api_keys rows = %d, want 1 — idempotency guard failed", apiKeysAfter2)
	}

	// And the stripe_events ledger records the event exactly once.
	var eventsRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stripe_events WHERE event_id = $1`, eventID).Scan(&eventsRows); err != nil {
		t.Fatalf("count stripe_events: %v", err)
	}
	if eventsRows != 1 {
		t.Errorf("stripe_events rows for %s = %d, want 1", eventID, eventsRows)
	}
}

// TestStripeWebhook_RejectsBadSignature — belt-and-braces: an attacker
// replaying a captured payload with the wrong secret must not even reach the
// idempotency logic. 400 is the correct response per Stripe's docs, and it
// prevents a bad actor from seeding fake event_ids into our stripe_events
// table to block legitimate replays.
func TestStripeWebhook_RejectsBadSignature(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_integration_test")
	srv, db := setup(t)

	payload := []byte(`{"id":"evt_bogus","object":"event","api_version":"2024-06-20","type":"checkout.session.completed","data":{"object":{}}}`)
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{
		Payload: payload,
		Secret:  "whsec_not_the_real_secret",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/stripe-webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", signed.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}

	// No stripe_events row must have been inserted — the signature gate is
	// strictly upstream of the idempotency INSERT.
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM stripe_events WHERE event_id = 'evt_bogus'`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Errorf("stripe_events inserted on bad signature: rows = %d, want 0", rows)
	}
}
