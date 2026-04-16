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
	"database/sql"
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
	if _, err := db.Exec(`TRUNCATE proof_drills, projects, api_keys RESTART IDENTITY CASCADE`); err != nil {
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

// seedAPIKey inserts a Pro API key for `userID` and returns the token the
// CLI would present. Using a fixed string (rather than the random hex the
// handler produces) keeps test assertions deterministic.
func seedAPIKey(t *testing.T, db *sql.DB, userID, tier string) string {
	t.Helper()
	token := fmt.Sprintf("aicap_pro_sk_test_%s", userID)
	if _, err := db.Exec(
		`INSERT INTO api_keys (user_id, token, subscription_tier) VALUES ($1, $2, $3)`,
		userID, token, tier,
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
// users each save a proof; each /api/history call must see only its own row.
func TestHistory_TenantScoping(t *testing.T) {
	srv, db := setup(t)
	alice := "00000000-0000-0000-0000-000000000010"
	bob := "00000000-0000-0000-0000-000000000020"
	aliceToken := seedAPIKey(t, db, alice, "pro")
	bobToken := seedAPIKey(t, db, bob, "pro")

	// Each user pushes one scan.
	for _, p := range []struct{ tok, commit string }{
		{aliceToken, "alice-sha"}, {bobToken, "bob-sha"},
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

	// Alice's /api/history must contain alice-sha and exactly one row.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/history", nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
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
