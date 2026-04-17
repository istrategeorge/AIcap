// Package auth provides Supabase JWT verification and API-key lookup
// for the AIcap SaaS backend.
//
// Two authentication schemes are supported:
//
//  1. Supabase session JWTs (HS256 signed with SUPABASE_JWT_SECRET).
//     Used by the browser app for dashboard endpoints. Derive the
//     caller's user ID from the token's `sub` claim — never trust a
//     userID supplied in the request body.
//
//  2. Long-lived API keys of the form `aicap_pro_sk_*` stored in the
//     `api_keys` table. Used by the CLI from CI/CD pipelines.
package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"aicap/pkg/httplog"

	"github.com/golang-jwt/jwt/v5"
)

// ctxKey is unexported to prevent collisions with other packages' context keys.
type ctxKey string

const (
	ctxUserID    ctxKey = "aicap.userID"
	ctxUserEmail ctxKey = "aicap.userEmail"
	ctxSubTier   ctxKey = "aicap.subscriptionTier"
)

// SupabaseClaims captures the subset of Supabase session-token claims we use.
type SupabaseClaims struct {
	Email string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

// ErrUnauthorized is returned when a request has no valid credentials.
var ErrUnauthorized = errors.New("unauthorized")

// VerifySupabaseJWT parses + verifies a Supabase-issued session token using
// the HS256 secret in SUPABASE_JWT_SECRET. Returns the claims on success.
func VerifySupabaseJWT(tokenString string) (*SupabaseClaims, error) {
	secret := os.Getenv("SUPABASE_JWT_SECRET")
	if secret == "" {
		return nil, errors.New("SUPABASE_JWT_SECRET not configured")
	}

	claims := &SupabaseClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if claims.Subject == "" {
		return nil, errors.New("token missing sub claim")
	}
	return claims, nil
}

// bearerToken extracts the raw token from an `Authorization: Bearer ...` header.
// Returns "" if the header is missing or malformed.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

// RequireSupabaseJWT is HTTP middleware that rejects requests lacking a valid
// Supabase session token. On success it injects the user ID and email into the
// request context (retrievable via UserID / UserEmail).
//
// Error mapping:
//   - Missing/malformed Authorization header → 401 (client must supply credentials)
//   - SUPABASE_JWT_SECRET not configured      → 500 (operator must set env var)
//   - Expired or invalid token                → 401 (client must re-authenticate)
//
// CORS preflight (OPTIONS) requests pass through unauthenticated so the wrapped
// handler can answer with the Access-Control-Allow-* headers the browser needs
// before it will send the real request with its Authorization header. A
// preflight has no Authorization header by design — rejecting it with 401
// blocks the real request from ever being sent and surfaces as a browser-side
// "Failed to fetch" with a misleading 401 in the network tab.
func RequireSupabaseJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		logger := httplog.From(r.Context())
		token := bearerToken(r)
		if token == "" {
			logger.Info("auth rejected",
				slog.String("reason", "missing bearer token"),
				slog.String("origin", r.Header.Get("Origin")),
			)
			http.Error(w, "Unauthorized: missing bearer token", http.StatusUnauthorized)
			return
		}
		claims, err := VerifySupabaseJWT(token)
		if err != nil {
			// Distinguish a missing server secret (operator error) from a bad
			// token (client error) so the caller isn't misled into thinking
			// their credentials are wrong when it's actually a config issue.
			if os.Getenv("SUPABASE_JWT_SECRET") == "" {
				logger.Error("SUPABASE_JWT_SECRET is not set — set this env var in your deployment to enable JWT auth")
				http.Error(w, "Server configuration error: JWT secret not configured. Contact the service administrator.", http.StatusInternalServerError)
				return
			}
			logger.Info("auth rejected",
				slog.String("reason", "jwt verify failed"),
				slog.Any("error", err),
			)
			http.Error(w, "Unauthorized: invalid or expired token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID, claims.Subject)
		ctx = context.WithValue(ctx, ctxUserEmail, claims.Email)
		next(w, r.WithContext(ctx))
	}
}

// APIKeyRecord holds the metadata returned from the api_keys lookup.
//
// Token intentionally omitted: after Wave 3b we only store the hash
// at rest, so no code path can hand a raw key back. If a caller needs
// to echo the key they must read it from the request's Authorization
// header — it is never loaded from the database.
type APIKeyRecord struct {
	UserID           string
	SubscriptionTier string
	ScansThisMonth   int
}

// HashAPIKey computes the canonical SHA-256 hash used to index an API key in
// the database. Exposed so handlers that need to write a row (generate-key,
// rotate-key, the Stripe webhook) can compute the same value LookupAPIKey
// would query with. Returns 64 lowercase hex chars — matches the column type
// produced by Postgres' `encode(sha256(...), 'hex')` in migration 00009.
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// LookupAPIKey verifies an `aicap_pro_sk_*` key exists in the database and
// returns the associated user_id + subscription metadata. The caller-supplied
// `key` is hashed with SHA-256 before the lookup — the plaintext token is
// never compared against a stored plaintext column (there is no such column
// after Wave 3b's migration 00009).
func LookupAPIKey(db *sql.DB, key string) (*APIKeyRecord, error) {
	if db == nil {
		return nil, errors.New("database not configured")
	}
	if key == "" {
		return nil, ErrUnauthorized
	}
	rec := &APIKeyRecord{}
	err := db.QueryRow(
		`SELECT user_id, COALESCE(subscription_tier, 'free'), COALESCE(scans_this_month, 0)
		 FROM api_keys WHERE token_hash = $1`, HashAPIKey(key),
	).Scan(&rec.UserID, &rec.SubscriptionTier, &rec.ScansThisMonth)
	if err == sql.ErrNoRows {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// RequireAPIKey is HTTP middleware that rejects requests without a valid
// aicap_pro_sk_* API key in the Authorization header. On success the userID,
// apiKey, and tier are injected into the request context.
//
// CORS preflight (OPTIONS) requests pass through unauthenticated; see the
// comment on RequireSupabaseJWT for why.
func RequireAPIKey(db *sql.DB, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next(w, r)
			return
		}
		logger := httplog.From(r.Context())
		token := bearerToken(r)
		if token == "" {
			logger.Info("auth rejected",
				slog.String("reason", "missing api key"),
				slog.String("origin", r.Header.Get("Origin")),
			)
			http.Error(w, "Unauthorized: missing API key", http.StatusUnauthorized)
			return
		}
		rec, err := LookupAPIKey(db, token)
		if err != nil {
			// err here is either ErrUnauthorized (the common case — wrong key) or
			// a real DB error. We log the message so the operator can distinguish,
			// but the client always sees the same 401 so a timing side-channel
			// can't probe for which keys exist.
			logger.Info("auth rejected",
				slog.String("reason", "api key lookup failed"),
				slog.Any("error", err),
			)
			http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID, rec.UserID)
		ctx = context.WithValue(ctx, ctxSubTier, rec.SubscriptionTier)
		next(w, r.WithContext(ctx))
	}
}

// UserID returns the authenticated user's id from the request context
// (populated by RequireSupabaseJWT or RequireAPIKey). Empty string if unset.
func UserID(r *http.Request) string {
	v, _ := r.Context().Value(ctxUserID).(string)
	return v
}

// UserEmail returns the authenticated user's email from the request context
// (populated by RequireSupabaseJWT only). Empty string if unset.
func UserEmail(r *http.Request) string {
	v, _ := r.Context().Value(ctxUserEmail).(string)
	return v
}

// SubscriptionTier returns the authenticated caller's subscription tier
// (populated by RequireAPIKey). Empty string if unset.
func SubscriptionTier(r *http.Request) string {
	v, _ := r.Context().Value(ctxSubTier).(string)
	return v
}
