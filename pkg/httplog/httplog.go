// Package httplog wires structured logging with slog and attaches a
// per-request ID to every log line a handler emits. The goal is to turn
// Render's log pane from a wall of free text into something grep-able:
//
//	{"time":"…","level":"INFO","msg":"auth rejected","request_id":"abc123",
//	 "method":"GET","path":"/api/history","reason":"missing bearer token"}
//
// A single request_id threads through every log line produced while serving
// that request, so you can reconstruct the full sequence of events from a
// client-reported symptom (the server also echoes the id back in the
// X-Request-ID response header).
package httplog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
)

// ctxKey is unexported so other packages can't collide with our context key.
type ctxKey int

const (
	loggerKey ctxKey = iota
	requestIDKey
)

// Init configures the process-wide default slog logger. Call once at
// startup. JSON output goes to stderr so container log collectors (Render,
// Docker, Kubernetes, stackdriver, loki …) can index it out of the box.
//
// LOG_LEVEL=debug turns on verbose logs for troubleshooting; unset defaults
// to info. We intentionally do not parse LOG_FORMAT — JSON-on-stderr is the
// only right answer for containerised deployments and we do not want
// ad-hoc dev-mode text handlers diverging from prod.
func Init() {
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}

// Middleware attaches a request ID and a child logger to the request
// context, and echoes the id in the X-Request-ID response header so a
// client seeing a 500 can paste the id back and let an operator find the
// server-side trace. Wrap every public handler in this.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Honour an upstream-supplied X-Request-ID so a proxy / load
		// balancer's trace id can continue through our logs. Generate one
		// when the caller didn't provide it.
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-ID", rid)

		logger := slog.Default().With(
			slog.String("request_id", rid),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
		)
		ctx := context.WithValue(r.Context(), loggerKey, logger)
		ctx = context.WithValue(ctx, requestIDKey, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// From returns the logger attached to ctx by Middleware. When ctx has no
// logger (unit tests, background goroutines) it falls back to the process
// default so callers never need a nil-check.
func From(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// RequestID returns the id attached to ctx, or "" if there isn't one.
// Useful when a handler wants to include the id in a response body so the
// client can correlate it to a server-side log entry.
func RequestID(ctx context.Context) string {
	if s, ok := ctx.Value(requestIDKey).(string); ok {
		return s
	}
	return ""
}

// newRequestID produces 16 hex chars of cryptographic randomness. Short
// enough to skim in logs; long enough that collisions within a running
// deployment's retention window are astronomically unlikely.
func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand on modern platforms does not fail
	return hex.EncodeToString(b[:])
}
