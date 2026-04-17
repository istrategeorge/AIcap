package httplog

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMiddleware_GeneratesAndEchoesID verifies that a request without an
// inbound X-Request-ID gets one, and that the server echoes the same id
// back on the response so clients can pin their symptom to a server trace.
func TestMiddleware_GeneratesAndEchoesID(t *testing.T) {
	var seen string
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if seen == "" {
		t.Fatal("handler saw empty request id")
	}
	if got := w.Header().Get("X-Request-ID"); got != seen {
		t.Errorf("X-Request-ID header = %q, want %q (match handler ctx)", got, seen)
	}
	if len(seen) != 16 {
		t.Errorf("id length = %d, want 16 hex chars", len(seen))
	}
}

// TestMiddleware_HonoursUpstreamID — if a load balancer / proxy set an id,
// we must not regenerate it. That's how distributed traces stitch together.
func TestMiddleware_HonoursUpstreamID(t *testing.T) {
	const upstream = "deadbeefcafe1234"
	var seen string
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", upstream)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if seen != upstream {
		t.Errorf("id = %q, want upstream %q", seen, upstream)
	}
}

// TestFrom_LoggerEmitsRequestID is the promise the rest of the codebase
// relies on: any log line written via httplog.From(ctx) carries the
// request_id automatically, without the caller having to remember to add it.
func TestFrom_LoggerEmitsRequestID(t *testing.T) {
	var buf bytes.Buffer
	// Rebind the default logger for the duration of this test so we can
	// capture output. slog's handler chain is immutable per-logger, so
	// this is the only clean way to assert on emitted records.
	prev := slog.Default()
	defer slog.SetDefault(prev)
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))

	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		From(r.Context()).Info("hello")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	req.Header.Set("X-Request-ID", "test-id-0001")
	h.ServeHTTP(httptest.NewRecorder(), req)

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("parse log: %v (raw=%q)", err, buf.String())
	}
	if rec["request_id"] != "test-id-0001" {
		t.Errorf("request_id = %v, want test-id-0001", rec["request_id"])
	}
	if rec["method"] != "GET" || rec["path"] != "/api/thing" {
		t.Errorf("log missing method/path context: %v", rec)
	}
}

// TestFrom_NoContext_FallsBack — defensive: if someone calls From with a
// bare context, they get the default logger rather than a nil panic.
func TestFrom_NoContext_FallsBack(t *testing.T) {
	l := From(context.Background())
	if l == nil {
		t.Fatal("From(context.Background()) returned nil")
	}
	// Smoke-test that it's usable.
	var buf bytes.Buffer
	prev := slog.Default()
	defer slog.SetDefault(prev)
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	From(context.Background()).Info("ok")
	if !strings.Contains(buf.String(), "ok") {
		t.Errorf("expected log output, got %q", buf.String())
	}
}
