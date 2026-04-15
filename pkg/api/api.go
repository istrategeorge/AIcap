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
	

	"aicap/pkg/types"
	"aicap/pkg/scanner"
	"aicap/pkg/compliance"

	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/checkout/session"
	"github.com/stripe/stripe-go/v79/webhook"
)

func RegisterRoutes(mux *http.ServeMux, db *sql.DB, isCloudSaaS bool) {
	// Helper function for consistent strict CORS handling
	setupCORS := func(w http.ResponseWriter) {
		allowedOrigin := os.Getenv("VITE_FRONTEND_URL")
		if allowedOrigin == "" {
			if !isCloudSaaS {
				allowedOrigin = "*" // Allow all for local headless / development without env
			} else {
				allowedOrigin = "https://aicap.vercel.app" // Default fallback for cloud
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
	}

	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		setupCORS(w)
		w.Header().Set("Content-Type", "application/json")

		// Run the scan
		bom := scanner.PerformScan(".")
		json.NewEncoder(w).Encode(bom)
	})

	// New endpoint to check or configure the Database Connection dynamically
	mux.HandleFunc("/api/db-config", func(w http.ResponseWriter, r *http.Request) {
		setupCORS(w)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
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
				db = nil // Disconnect
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

	// New endpoint to save the Proof Drill to Supabase
	mux.HandleFunc("/api/save-proof", func(w http.ResponseWriter, r *http.Request) {
		setupCORS(w)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		// Phase 7: API Key Authentication for Cloud SaaS & Rate Limiting
		if isCloudSaaS {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized: Missing or malformed API Key", http.StatusUnauthorized)
				return
			}
			apiKey := strings.TrimPrefix(authHeader, "Bearer ")

			var userID, subTier string
			var scansUsed int
			// Using COALESCE for backward compatibility before migration
			err := db.QueryRow("SELECT user_id, COALESCE(subscription_tier, 'free'), COALESCE(scans_this_month, 0) FROM api_keys WHERE token = $1", apiKey).Scan(&userID, &subTier, &scansUsed)
			if err != nil {
				http.Error(w, "Unauthorized: Invalid API Key", http.StatusUnauthorized)
				return
			}

			// Apply Rate Limiting based on Tier
			if subTier == "free" && scansUsed >= 10 {
				http.Error(w, "Payment Required: Free tier limit of 10 cloud syncs reached. Please upgrade to Pro.", http.StatusPaymentRequired)
				return
			}

			// Increment usage tracking
			_, err = db.Exec("UPDATE api_keys SET scans_this_month = scans_this_month + 1 WHERE token = $1", apiKey)
			if err != nil {
				log.Printf("Failed to increment usage tracking for API Key: %v", err)
			}
		}

		var bom types.AIBOM
		json.NewDecoder(r.Body).Decode(&bom)
		bomJSON, _ := json.Marshal(bom)

		// 1. Upsert the Project (avoid creating duplicates)
		var projectID string
		err := db.QueryRow(`
			INSERT INTO projects (name) VALUES ($1)
			ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
			RETURNING id`, bom.ProjectName).Scan(&projectID)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 2. Create the immutable Proof Drill ledger entry
		commitSha := bom.CommitSha
		if commitSha == "" {
			commitSha = "local-dev-uncommitted"
		}
		annexIVMarkdown := compliance.GenerateAnnexIVMarkdown(bom)

		// Generate a real SHA-256 cryptographic hash
		hash := sha256.New()
		hash.Write([]byte(commitSha))
		hash.Write(bomJSON)
		cryptoHash := hex.EncodeToString(hash.Sum(nil))

		_, err = db.Exec(`
			INSERT INTO proof_drills (project_id, commit_sha, ai_bom_json, annex_iv_markdown, crypto_hash)
			VALUES ($1, $2, $3, $4, $5)`,
			projectID, commitSha, bomJSON, annexIVMarkdown, cryptoHash,
		)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	// New endpoint to retrieve historical proof drills
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		setupCORS(w)
		w.Header().Set("Content-Type", "application/json")

		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		rows, err := db.Query(`
			SELECT p.name, pd.commit_sha, pd.crypto_hash, pd.created_at
			FROM proof_drills pd
			JOIN projects p ON pd.project_id = p.id
			ORDER BY pd.created_at DESC
			LIMIT 5
		`)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var records []types.ProofRecord
		for rows.Next() {
			var rec types.ProofRecord
			rows.Scan(&rec.ProjectName, &rec.CommitSha, &rec.CryptoHash, &rec.Timestamp)
			records = append(records, rec)
		}

		json.NewEncoder(w).Encode(records)
	})

	// New endpoint to fetch a specific historical proof drill markdown
	mux.HandleFunc("/api/proof", func(w http.ResponseWriter, r *http.Request) {
		setupCORS(w)
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
		err := db.QueryRow("SELECT annex_iv_markdown FROM proof_drills WHERE crypto_hash = $1", hash).Scan(&markdown)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"markdown": markdown})
	})

	// Endpoint to create a Stripe Checkout Session
	mux.HandleFunc("/api/create-checkout-session", func(w http.ResponseWriter, r *http.Request) {
		setupCORS(w)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

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

		// We expect the email from the authenticated user to create the checkout session
		var requestBody struct {
			UserEmail string `json:"userEmail"`
			UserID    string `json:"userID"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
		if stripe.Key == "" {
			log.Println("STRIPE_SECRET_KEY is not set.")
			http.Error(w, "Stripe secret key not configured", http.StatusInternalServerError)
			return
		}

		// Define a product or price ID in Stripe Dashboard (e.g., 'price_12345')
		// For MVP, we use a fixed price. In production, this would be dynamic.
		priceID := "price_1Pdtg1E5iL2Zl43n5G4YhI9t" // Replace with your actual Stripe Price ID
		if os.Getenv("STRIPE_PRICE_ID") != "" {
			priceID = os.Getenv("STRIPE_PRICE_ID")
		}

		frontendURL := os.Getenv("VITE_FRONTEND_URL")
		if frontendURL == "" {
			frontendURL = "http://localhost:5173" // fallback for local testing
		}

		params := &stripe.CheckoutSessionParams{
			LineItems: []*stripe.CheckoutSessionLineItemParams{
				{
					Price:    stripe.String(priceID),
					Quantity: stripe.Int64(1),
				},
			},
			Mode:          stripe.String(string(stripe.CheckoutSessionModeSubscription)),
			SuccessURL:    stripe.String(frontendURL + "/?session_id={CHECKOUT_SESSION_ID}"),
			CancelURL:     stripe.String(frontendURL + "/"),
			CustomerEmail: stripe.String(requestBody.UserEmail),
			Metadata: map[string]string{
				"user_id": requestBody.UserID,
			},
		}

		checkoutSession, err := session.New(params)
		if err != nil {
			log.Printf("Error creating checkout session: %v", err)
			http.Error(w, fmt.Sprintf("Stripe Error: %v", err), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"sessionId": checkoutSession.ID, "url": checkoutSession.URL})
	})

	// Stripe Webhook Handler
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
			var checkoutSession stripe.CheckoutSession
			err := json.Unmarshal(event.Data.Raw, &checkoutSession)
			if err != nil {
				log.Printf("Error parsing webhook JSON: %v", err)
				http.Error(w, "Error parsing webhook JSON", http.StatusBadRequest)
				return
			}

			userID := checkoutSession.Metadata["user_id"]
			log.Printf("Checkout completed for customer: %s, UserID: %s", checkoutSession.CustomerEmail, userID)

			// Auto-provision API key for the new subscriber
			if userID != "" {
				var existingKey string
				err := db.QueryRow("SELECT token FROM api_keys WHERE user_id = $1", userID).Scan(&existingKey)
				if err != nil {
					// No key exists — generate and provision one
					keyBytes := make([]byte, 24)
					if _, keyErr := rand.Read(keyBytes); keyErr == nil {
						apiKey := "aicap_pro_sk_" + hex.EncodeToString(keyBytes)
						_, insertErr := db.Exec(
							"INSERT INTO api_keys (user_id, token, stripe_customer_id, subscription_tier) VALUES ($1, $2, $3, 'pro')",
							userID, apiKey, checkoutSession.Customer.ID,
						)
						if insertErr != nil {
							log.Printf("Failed to provision API key for user %s: %v", userID, insertErr)
						} else {
							log.Printf("API key provisioned (Pro Tier) for user %s", userID)
						}
					}
				} else {
					log.Printf("User %s already has an API key, upgrading to Pro", userID)
					_, updateErr := db.Exec("UPDATE api_keys SET subscription_tier = 'pro', stripe_customer_id = $1 WHERE user_id = $2", checkoutSession.Customer.ID, userID)
					if updateErr != nil {
						log.Printf("Failed to upgrade API key to Pro for user %s: %v", userID, updateErr)
					}
				}
			}

		case "customer.subscription.deleted":
			// Subscription cancelled — revoke API access
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				log.Printf("Error parsing subscription deleted event: %v", err)
				break
			}
			log.Printf("Subscription deleted for customer: %s", sub.Customer.ID)

			// Revoke the API key associated with this customer
			result, err := db.Exec("DELETE FROM api_keys WHERE stripe_customer_id = $1", sub.Customer.ID)
			if err != nil {
				log.Printf("Failed to revoke API key for customer %s: %v", sub.Customer.ID, err)
			} else {
				rowsAffected, _ := result.RowsAffected()
				log.Printf("Revoked %d API key(s) for customer %s", rowsAffected, sub.Customer.ID)
			}

		case "invoice.payment_failed":
			// Payment failed — log it but don't revoke immediately (Stripe retries)
			var invoice stripe.Invoice
			if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
				log.Printf("Error parsing invoice event: %v", err)
				break
			}
			log.Printf("Payment failed for customer: %s, invoice: %s, attempt: %d",
				invoice.Customer.ID, invoice.ID, invoice.AttemptCount)

			// After 3 failed attempts, revoke access
			if invoice.AttemptCount >= 3 {
				log.Printf("Max retry attempts reached for customer %s. Revoking API key.", invoice.Customer.ID)
				db.Exec("DELETE FROM api_keys WHERE stripe_customer_id = $1", invoice.Customer.ID)
			}

		case "customer.subscription.updated":
			var sub stripe.Subscription
			if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
				log.Printf("Error parsing subscription update event: %v", err)
				break
			}
			log.Printf("Subscription updated for customer: %s, status: %s", sub.Customer.ID, sub.Status)

		default:
			log.Printf("Unhandled event type: %s", event.Type)
		}

		w.WriteHeader(http.StatusOK)
	})

	// Secure server-side API key generation endpoint
	mux.HandleFunc("/api/generate-key", func(w http.ResponseWriter, r *http.Request) {
		setupCORS(w)
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

		var reqBody struct {
			UserID string `json:"userID"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil || reqBody.UserID == "" {
			http.Error(w, "Invalid request: userID required", http.StatusBadRequest)
			return
		}

		// Check if user already has a key
		var existingKey string
		err := db.QueryRow("SELECT token FROM api_keys WHERE user_id = $1", reqBody.UserID).Scan(&existingKey)
		if err == nil {
			// Key already exists, return it
			json.NewEncoder(w).Encode(map[string]string{"apiKey": existingKey})
			return
		}

		// Generate a cryptographically secure API key
		keyBytes := make([]byte, 24)
		if _, err := rand.Read(keyBytes); err != nil {
			http.Error(w, "Failed to generate key", http.StatusInternalServerError)
			return
		}
		apiKey := "aicap_pro_sk_" + hex.EncodeToString(keyBytes)

		_, err = db.Exec("INSERT INTO api_keys (user_id, token) VALUES ($1, $2)", reqBody.UserID, apiKey)
		if err != nil {
			http.Error(w, "Failed to store key: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"apiKey": apiKey})
	})

}

