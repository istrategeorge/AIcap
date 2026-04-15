package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"aicap/pkg/auth"
	"aicap/pkg/compliance"
	"aicap/pkg/scanner"
	"aicap/pkg/types"

	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/checkout/session"
	"github.com/stripe/stripe-go/v79/webhook"
)

// RegisterRoutes wires all AIcap HTTP handlers onto `mux`. `db` may be nil in
// local/headless mode — in that case the SaaS-only endpoints short-circuit to
// a 500. `isCloudSaaS` is true when SUPABASE_DB_URL was set at boot and turns
// on authentication + disables local-dev-only conveniences (db-config POST,
// filesystem scanning).
func RegisterRoutes(mux *http.ServeMux, db *sql.DB, isCloudSaaS bool) {
	// Build the CORS origin allowlist once at startup.
	// VITE_FRONTEND_URL can be a single origin or a comma-separated list.
	allowedOrigins := parseAllowedOrigins(os.Getenv("VITE_FRONTEND_URL"), isCloudSaaS)

	// cors applies consistent CORS headers for browser clients.
	// For CLI callers (no Origin header) it is a no-op.
	cors := func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return
		}
		if isAllowedOrigin(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
	}

	// --- Health --------------------------------------------------------------
	// /healthz is used by Render/K8s liveness probes. It reports DB status
	// without leaking any configuration details.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		status := "ok"
		code := http.StatusOK
		if isCloudSaaS && (db == nil || db.Ping() != nil) {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"status": status})
	})

	// --- Local scan (dev only) ----------------------------------------------
	// /api/scan runs a filesystem scan on the server's working directory. That
	// is only safe during local development; in cloud mode we refuse to expose
	// it because scanning belongs in the CLI (which runs inside the customer's
	// CI/CD pipeline and never ships source to us).
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		if isCloudSaaS {
			http.Error(w, "Not available in cloud mode — use the AIcap CLI", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		bom := scanner.PerformScan(".")
		json.NewEncoder(w).Encode(bom)
	})

	// --- DB config (dev only) -----------------------------------------------
	// /api/db-config was a local-dev convenience that let the UI point a
	// running Go backend at any Postgres URL. In cloud mode exposing this
	// endpoint would let any anonymous caller repoint the production database,
	// so it is disabled entirely there.
	mux.HandleFunc("/api/db-config", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			return
		}

		if isCloudSaaS {
			http.Error(w, "Not available in cloud mode", http.StatusNotFound)
			return
		}

		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]bool{"connected": db != nil})
			return
		}

		if r.Method == "POST" {
			var req struct {
				URL     string `json:"url"`
				Enabled bool   `json:"enabled"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if !req.Enabled {
				db = nil
				json.NewEncoder(w).Encode(map[string]bool{"connected": false})
				return
			}
			newDB, err := sql.Open("postgres", req.URL)
			if err == nil && newDB.Ping() == nil {
				db = newDB
				json.NewEncoder(w).Encode(map[string]bool{"connected": true})
			} else {
				http.Error(w, "Failed to connect to database", http.StatusBadRequest)
			}
		}
	})

	// --- Proof drill persistence --------------------------------------------
	// /api/save-proof is called by the CLI from CI/CD pipelines. It requires
	// a valid aicap_pro_sk_* API key, enforces per-tier rate limits, and
	// records the authenticated user's ID on each ledger row so /api/history
	// and /api/proof can filter to the caller's own projects.
	saveProof := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		apiKey := auth.APIKey(r)
		tier := auth.SubscriptionTier(r)

		// Re-read scans_this_month inside the handler so the rate-limit check
		// and increment are as close to atomic as we can get without a tx.
		var scansUsed int
		if err := db.QueryRow(
			"SELECT COALESCE(scans_this_month, 0) FROM api_keys WHERE token = $1", apiKey,
		).Scan(&scansUsed); err != nil {
			http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
			return
		}
		if tier == "free" && scansUsed >= 10 {
			http.Error(w, "Payment Required: Free tier limit of 10 cloud syncs reached. Please upgrade to Pro.", http.StatusPaymentRequired)
			return
		}
		if _, err := db.Exec(
			"UPDATE api_keys SET scans_this_month = scans_this_month + 1 WHERE token = $1", apiKey,
		); err != nil {
			log.Printf("Failed to increment usage tracking for API Key: %v", err)
		}

		var bom types.AIBOM
		json.NewDecoder(r.Body).Decode(&bom)
		bomJSON, _ := json.Marshal(bom)

		var projectID string
		err := db.QueryRow(`
			INSERT INTO projects (name) VALUES ($1)
			ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			RETURNING id`, bom.ProjectName).Scan(&projectID)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		commitSha := bom.CommitSha
		if commitSha == "" {
			commitSha = "local-dev-uncommitted"
		}
		annexIVMarkdown := compliance.GenerateAnnexIVMarkdown(bom)

		h := sha256.New()
		h.Write([]byte(commitSha))
		h.Write(bomJSON)
		cryptoHash := hex.EncodeToString(h.Sum(nil))

		// Use sql.NullString so that an empty userID (possible during a
		// schema-migration race where the middleware ran on old code) is stored
		// as NULL rather than rejected as an invalid UUID literal.
		nullableUserID := sql.NullString{String: userID, Valid: userID != ""}

		_, err = db.Exec(`
			INSERT INTO proof_drills (project_id, user_id, commit_sha, ai_bom_json, annex_iv_markdown, crypto_hash)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			projectID, nullableUserID, commitSha, bomJSON, annexIVMarkdown, cryptoHash,
		)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
	if isCloudSaaS {
		mux.HandleFunc("/api/save-proof", auth.RequireAPIKey(db, saveProof))
	} else {
		mux.HandleFunc("/api/save-proof", saveProof)
	}

	// --- History ------------------------------------------------------------
	// /api/history returns the caller's most recent proof drills. Requires an
	// API key in cloud mode so we can scope results to their user_id and never
	// leak another tenant's ledger.
	historyHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Content-Type", "application/json")
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		var rows *sql.Rows
		var err error
		if isCloudSaaS {
			userID := auth.UserID(r)
			// Include rows where user_id IS NULL as a migration bridge:
			// scans saved by the CLI before Wave 1 was deployed land with
			// user_id = NULL. Once a user runs a fresh scan those rows get
			// proper attribution; the NULL clause ensures the old ones stay
			// visible in the meantime rather than silently disappearing.
			rows, err = db.Query(`
				SELECT p.name, pd.commit_sha, pd.crypto_hash, pd.created_at
				FROM proof_drills pd
				JOIN projects p ON pd.project_id = p.id
				WHERE pd.user_id = $1 OR pd.user_id IS NULL
				ORDER BY pd.created_at DESC
				LIMIT 25`, userID)
		} else {
			rows, err = db.Query(`
				SELECT p.name, pd.commit_sha, pd.crypto_hash, pd.created_at
				FROM proof_drills pd
				JOIN projects p ON pd.project_id = p.id
				ORDER BY pd.created_at DESC
				LIMIT 25`)
		}
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		records := []types.ProofRecord{}
		for rows.Next() {
			var rec types.ProofRecord
			rows.Scan(&rec.ProjectName, &rec.CommitSha, &rec.CryptoHash, &rec.Timestamp)
			records = append(records, rec)
		}
		json.NewEncoder(w).Encode(records)
	}
	if isCloudSaaS {
		mux.HandleFunc("/api/history", auth.RequireAPIKey(db, historyHandler))
	} else {
		mux.HandleFunc("/api/history", historyHandler)
	}

	// --- Single proof -------------------------------------------------------
	// /api/proof returns the Annex IV markdown for a given hash. Scoped to the
	// caller's user_id in cloud mode so hash guessing can't cross tenants.
	proofHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Content-Type", "application/json")
		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}
		hash := r.URL.Query().Get("hash")
		if hash == "" {
			http.Error(w, "Missing hash parameter", http.StatusBadRequest)
			return
		}

		var markdown string
		var err error
		if isCloudSaaS {
			userID := auth.UserID(r)
			// Same bridge as /api/history: allow fetching NULL-user_id rows
			// that predate the Wave 1 attribution rollout.
			err = db.QueryRow(
				"SELECT annex_iv_markdown FROM proof_drills WHERE crypto_hash = $1 AND (user_id = $2 OR user_id IS NULL)",
				hash, userID,
			).Scan(&markdown)
		} else {
			err = db.QueryRow(
				"SELECT annex_iv_markdown FROM proof_drills WHERE crypto_hash = $1", hash,
			).Scan(&markdown)
		}
		if err == sql.ErrNoRows {
			http.Error(w, "Proof drill not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"markdown": markdown})
	}
	if isCloudSaaS {
		mux.HandleFunc("/api/proof", auth.RequireAPIKey(db, proofHandler))
	} else {
		mux.HandleFunc("/api/proof", proofHandler)
	}

	// --- Stripe checkout ----------------------------------------------------
	// /api/create-checkout-session derives user_id + email from the verified
	// Supabase JWT; the request body is ignored for those fields so a caller
	// cannot claim someone else's identity.
	checkoutHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment and database connection", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)
		userEmail := auth.UserEmail(r)

		stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
		if stripe.Key == "" {
			log.Println("STRIPE_SECRET_KEY is not set.")
			http.Error(w, "Stripe secret key not configured", http.StatusInternalServerError)
			return
		}

		priceID := "price_1Pdtg1E5iL2Zl43n5G4YhI9t"
		if v := os.Getenv("STRIPE_PRICE_ID"); v != "" {
			priceID = v
		}

		frontendURL := os.Getenv("VITE_FRONTEND_URL")
		if frontendURL == "" {
			frontendURL = "http://localhost:5173"
		} else if idx := strings.Index(frontendURL, ","); idx >= 0 {
			// If an allowlist was supplied, use the first entry for redirects.
			frontendURL = strings.TrimSpace(frontendURL[:idx])
		}

		params := &stripe.CheckoutSessionParams{
			LineItems: []*stripe.CheckoutSessionLineItemParams{
				{Price: stripe.String(priceID), Quantity: stripe.Int64(1)},
			},
			Mode:          stripe.String(string(stripe.CheckoutSessionModeSubscription)),
			SuccessURL:    stripe.String(frontendURL + "/?session_id={CHECKOUT_SESSION_ID}"),
			CancelURL:     stripe.String(frontendURL + "/"),
			CustomerEmail: stripe.String(userEmail),
			Metadata:      map[string]string{"user_id": userID},
		}
		checkoutSession, err := session.New(params)
		if err != nil {
			log.Printf("Error creating checkout session: %v", err)
			http.Error(w, fmt.Sprintf("Stripe Error: %v", err), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"sessionId": checkoutSession.ID, "url": checkoutSession.URL})
	}
	mux.HandleFunc("/api/create-checkout-session", auth.RequireSupabaseJWT(checkoutHandler))

	// --- Stripe webhook -----------------------------------------------------
	// The webhook itself is authenticated by Stripe's signature, not by us.
	// customerID() guards against nil pointer panics on test-clock events
	// where the Customer reference can be absent.
	mux.HandleFunc("/api/stripe-webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "Webhook features require cloud deployment and database connection", http.StatusInternalServerError)
			return
		}

		const MaxBodyBytes = int64(65536)
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading request body: %v", err), http.StatusServiceUnavailable)
			return
		}
		endpointSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
		event, err := webhook.ConstructEvent(payload, r.Header.Get("stripe-signature"), endpointSecret)
		if err != nil {
			log.Printf("Error verifying webhook signature: %v", err)
			http.Error(w, "Webhook signature verification failed", http.StatusBadRequest)
			return
		}

		switch event.Type {
		case "checkout.session.completed":
			var cs stripe.CheckoutSession
			if err := json.Unmarshal(event.Data.Raw, &cs); err != nil {
				log.Printf("Error parsing webhook JSON: %v", err)
				http.Error(w, "Error parsing webhook JSON", http.StatusBadRequest)
				return
			}
			userID := cs.Metadata["user_id"]
			customerID := customerID(cs.Customer)
			log.Printf("Checkout completed: customer=%s userID=%s", customerID, userID)
			if userID == "" {
				log.Printf("checkout.session.completed missing user_id metadata — skipping provision")
				break
			}

			var existingKey string
			err := db.QueryRow("SELECT token FROM api_keys WHERE user_id = $1", userID).Scan(&existingKey)
			if err != nil {
				keyBytes := make([]byte, 24)
				if _, keyErr := rand.Read(keyBytes); keyErr == nil {
					apiKey := "aicap_pro_sk_" + hex.EncodeToString(keyBytes)
					if _, insertErr := db.Exec(
						"INSERT INTO api_keys (user_id, token, stripe_customer_id, subscription_tier) VALUES ($1, $2, $3, 'pro')",
						userID, apiKey, customerID,
					); insertErr != nil {
						log.Printf("Failed to provision API key for user %s: %v", userID, insertErr)
					} else {
						log.Printf("API key provisioned (Pro Tier) for user %s", userID)
					}
				}
			} else {
				log.Printf("User %s already has an API key, upgrading to Pro", userID)
				if _, updateErr := db.Exec(
					"UPDATE api_keys SET subscription_tier = 'pro', stripe_customer_id = $1 WHERE user_id = $2",
					customerID, userID,
				); updateErr != nil {
					log.Printf("Failed to upgrade API key to Pro for user %s: %v", userID, updateErr)
				}
			}

		case "customer.subscription.deleted":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				log.Printf("Error parsing subscription deleted event: %v", err)
				break
			}
			cid := customerID(sub.Customer)
			if cid == "" {
				break
			}
			log.Printf("Subscription deleted for customer: %s", cid)
			result, err := db.Exec("DELETE FROM api_keys WHERE stripe_customer_id = $1", cid)
			if err != nil {
				log.Printf("Failed to revoke API key for customer %s: %v", cid, err)
			} else {
				rows, _ := result.RowsAffected()
				log.Printf("Revoked %d API key(s) for customer %s", rows, cid)
			}

		case "invoice.payment_failed":
			var invoice stripe.Invoice
			if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
				log.Printf("Error parsing invoice event: %v", err)
				break
			}
			cid := customerID(invoice.Customer)
			log.Printf("Payment failed: customer=%s invoice=%s attempt=%d",
				cid, invoice.ID, invoice.AttemptCount)
			if cid != "" && invoice.AttemptCount >= 3 {
				log.Printf("Max retry attempts reached for customer %s. Revoking API key.", cid)
				db.Exec("DELETE FROM api_keys WHERE stripe_customer_id = $1", cid)
			}

		case "customer.subscription.updated":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				log.Printf("Error parsing subscription update event: %v", err)
				break
			}
			log.Printf("Subscription updated: customer=%s status=%s", customerID(sub.Customer), sub.Status)

		default:
			log.Printf("Unhandled event type: %s", event.Type)
		}

		w.WriteHeader(http.StatusOK)
	})

	// --- API key issuance ---------------------------------------------------
	// /api/generate-key returns (or creates) the authenticated user's API key.
	// userID comes from the verified JWT, never from the request body.
	generateKeyHandler := func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isCloudSaaS || db == nil {
			http.Error(w, "SaaS features require cloud deployment", http.StatusInternalServerError)
			return
		}

		userID := auth.UserID(r)

		var existingKey string
		err := db.QueryRow("SELECT token FROM api_keys WHERE user_id = $1", userID).Scan(&existingKey)
		if err == nil {
			json.NewEncoder(w).Encode(map[string]string{"apiKey": existingKey})
			return
		}

		keyBytes := make([]byte, 24)
		if _, err := rand.Read(keyBytes); err != nil {
			http.Error(w, "Failed to generate key", http.StatusInternalServerError)
			return
		}
		apiKey := "aicap_pro_sk_" + hex.EncodeToString(keyBytes)

		if _, err := db.Exec(
			"INSERT INTO api_keys (user_id, token) VALUES ($1, $2)", userID, apiKey,
		); err != nil {
			http.Error(w, "Failed to store key: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"apiKey": apiKey})
	}
	mux.HandleFunc("/api/generate-key", auth.RequireSupabaseJWT(generateKeyHandler))
}

// parseAllowedOrigins splits a comma-separated VITE_FRONTEND_URL into a set of
// trimmed origins. In local mode (no DB configured) we fall back to "*" so
// `go run` against a Vite dev server on an arbitrary port still works.
func parseAllowedOrigins(env string, isCloudSaaS bool) []string {
	if env == "" {
		if isCloudSaaS {
			return []string{"https://aicap.vercel.app"}
		}
		return []string{"*"}
	}
	parts := strings.Split(env, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isAllowedOrigin(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}

// customerID safely extracts a Stripe customer ID from a potentially-nil
// *stripe.Customer reference. Returns "" when the pointer is nil — this
// shows up on test-clock events and certain partial payloads and would
// otherwise cause a nil-pointer dereference.
func customerID(c *stripe.Customer) string {
	if c == nil {
		return ""
	}
	return c.ID
}
