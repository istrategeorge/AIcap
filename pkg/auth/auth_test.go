package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-supabase-jwt-secret-never-use-in-prod"

// mintToken creates a signed Supabase-style token for tests.
func mintToken(t *testing.T, sub, email string, exp time.Time) string {
	t.Helper()
	claims := &SupabaseClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestVerifySupabaseJWT_ValidToken(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	tok := mintToken(t, "user-123", "dev@example.com", time.Now().Add(time.Hour))

	claims, err := VerifySupabaseJWT(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-123")
	}
	if claims.Email != "dev@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "dev@example.com")
	}
}

func TestVerifySupabaseJWT_Expired(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	tok := mintToken(t, "user-123", "", time.Now().Add(-time.Minute))

	if _, err := VerifySupabaseJWT(tok); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifySupabaseJWT_WrongSecret(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	tok := mintToken(t, "user-123", "", time.Now().Add(time.Hour))

	// Rotate the server secret; previously-minted tokens must stop verifying.
	t.Setenv("SUPABASE_JWT_SECRET", "different-secret")
	if _, err := VerifySupabaseJWT(tok); err == nil {
		t.Fatal("expected error when secret rotates")
	}
}

func TestVerifySupabaseJWT_MissingSub(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	claims := &SupabaseClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))

	if _, err := VerifySupabaseJWT(tok); err == nil {
		t.Fatal("expected error when sub claim is missing")
	}
}

func TestVerifySupabaseJWT_NoSecretConfigured(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", "")
	if _, err := VerifySupabaseJWT("anything"); err == nil {
		t.Fatal("expected error when SUPABASE_JWT_SECRET unset")
	}
}

// TestVerifySupabaseJWT_AlgConfusion guards against the classic "none" /
// RSA-as-HMAC attack: an attacker swaps the alg header and signs with the
// public key, hoping the server uses the public key as an HMAC secret. Our
// keyFunc rejects anything that isn't HMAC.
func TestVerifySupabaseJWT_AlgConfusion(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	// Craft an alg=none token manually. jwt/v5 refuses to sign with "none"
	// on the client side, so we build one by hand.
	unsigned := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiJ1c2VyLTEyMyIsImV4cCI6OTk5OTk5OTk5OX0."
	if _, err := VerifySupabaseJWT(unsigned); err == nil {
		t.Fatal("expected error for alg=none token")
	}
}

func TestRequireSupabaseJWT_RejectsMissingHeader(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	called := false
	h := RequireSupabaseJWT(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if called {
		t.Error("inner handler should not run without credentials")
	}
}

// TestRequireSupabaseJWT_MissingSecretReturns500 ensures that an unconfigured
// SUPABASE_JWT_SECRET is surfaced as a server error (500), not a client auth
// error (401). A 401 would mislead the caller into retrying with different
// credentials when the real fix is an operator env-var configuration.
func TestRequireSupabaseJWT_MissingSecretReturns500(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", "") // simulate unconfigured deployment
	tok := "any.token.value"
	h := RequireSupabaseJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/create-checkout-session", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (server config error)", w.Code)
	}
}

func TestRequireSupabaseJWT_RejectsMalformedHeader(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	h := RequireSupabaseJWT(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "NotBearer foo")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireSupabaseJWT_InjectsUserContext(t *testing.T) {
	t.Setenv("SUPABASE_JWT_SECRET", testSecret)
	tok := mintToken(t, "user-abc", "alice@example.com", time.Now().Add(time.Hour))

	var gotID, gotEmail string
	h := RequireSupabaseJWT(func(w http.ResponseWriter, r *http.Request) {
		gotID = UserID(r)
		gotEmail = UserEmail(r)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if gotID != "user-abc" {
		t.Errorf("UserID = %q, want %q", gotID, "user-abc")
	}
	if gotEmail != "alice@example.com" {
		t.Errorf("UserEmail = %q, want %q", gotEmail, "alice@example.com")
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header, want string
	}{
		{"Bearer abc.def.ghi", "abc.def.ghi"},
		{"bearer abc", ""},           // case-sensitive scheme per RFC
		{"Bearer", ""},                // missing token part
		{"", ""},                      // missing header
		{"Basic dXNlcjpwYXNz", ""},    // wrong scheme
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		if got := bearerToken(r); got != c.want {
			t.Errorf("bearerToken(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}
