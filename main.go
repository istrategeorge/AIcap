package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/checkout/session"
	"github.com/stripe/stripe-go/v79/webhook"
)

// AIDependency represents an identified AI library/model in the codebase
type AIDependency struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
	License     string `json:"license,omitempty"`
}

// FinOpsFinding represents a cloud cost optimization warning
type FinOpsFinding struct {
	Resource    string `json:"resource"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
}

// AIBOM represents the final Software Bill of Materials for AI
type AIBOM struct {
	ProjectName      string            `json:"projectName"`
	CommitSha        string            `json:"commitSha,omitempty"`
	ScannedFiles     int               `json:"scannedFiles"`
	Dependencies     []AIDependency    `json:"dependencies"`
	FinOps           []FinOpsFinding   `json:"finOps"`
	PolicyViolations []PolicyViolation `json:"policyViolations,omitempty"`
	Compliance       string            `json:"complianceStatus"`
}

// PolicyViolation represents a policy-as-code rule violation
type PolicyViolation struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
}

// PolicyConfig represents the .aicap.yml policy-as-code configuration
type PolicyConfig struct {
	AllowedModels    []string `json:"allowedModels"`
	BlockedModels    []string `json:"blockedModels"`
	MaxRiskLevel     string   `json:"maxRiskLevel"`
	BlockOnHighRisk  bool     `json:"blockOnHighRisk"`
	RequireLicenses  bool     `json:"requireLicenses"`
	AllowedLicenses  []string `json:"allowedLicenses"`
}

// Map of known AI libraries and their assumed regulatory risk (MVP level)
type LibraryMeta struct {
	Risk string `json:"risk"`
	Desc string `json:"desc"`
}

// ProofRecord represents a historical compliance scan
type ProofRecord struct {
	ProjectName string `json:"projectName"`
	CommitSha   string `json:"commitSha"`
	CryptoHash  string `json:"cryptoHash"`
	Timestamp   string `json:"timestamp"`
}

var targetAILibraries map[string]LibraryMeta

var targetModels []string

// LicenseMapping links a local/hardcoded model to its registry or proprietary license
type LicenseMapping struct {
	HFID    string `json:"hf_id,omitempty"`
	License string `json:"license,omitempty"`
}

var modelLicenseMap map[string]LicenseMapping

// Global database connection pool
var db *sql.DB

// isCloudSaaS determines if the server is running in managed cloud mode
// In production, the Stripe webhook handler will always run in cloudSaaS mode
// The local `db-config` endpoint allows local developers to simulate a DB.
// We rely on SUPABASE_DB_URL presence to indicate cloud vs local
var isCloudSaaS bool

//go:embed libraries.json models.json licenses.json
var embeddedFiles embed.FS

func init() {
	libFile, err := embeddedFiles.ReadFile("libraries.json")
	if err != nil {
		log.Println("Could not load libraries.json, using default libraries.")
		targetAILibraries = map[string]LibraryMeta{
			"openai":       {"High", "External LLM API Call (OpenAI)"},
			"anthropic":    {"High", "External LLM API Call (Anthropic)"},
			"langchain":    {"Medium", "LLM Orchestration Framework"},
			"torch":        {"High", "PyTorch Machine Learning Framework"},
			"tensorflow":   {"High", "TensorFlow Machine Learning Framework"},
			"scikit-learn": {"Low", "Traditional Machine Learning Library"},
			"transformers": {"High", "Hugging Face Transformers"},
		}
	} else {
		if err := json.Unmarshal(libFile, &targetAILibraries); err != nil {
			log.Printf("Error parsing libraries.json: %v. Using defaults.", err)
		}
	}

	file, err := embeddedFiles.ReadFile("models.json")
	if err != nil {
		log.Println("Could not load models.json, using default models.")
		targetModels = []string{"gpt-4", "claude-3", "llama-3"}
		return
	}
	if err := json.Unmarshal(file, &targetModels); err != nil {
		log.Printf("Error parsing models.json: %v. Using defaults.", err)
		targetModels = []string{"gpt-4", "claude-3", "llama-3"}
	}

	licFile, err := embeddedFiles.ReadFile("licenses.json")
	if err != nil {
		log.Println("Could not load licenses.json, using default license mappings.")
		modelLicenseMap = map[string]LicenseMapping{
			"llama-3":  {HFID: "meta-llama/Meta-Llama-3-8B"},
			"mixtral":  {HFID: "mistralai/Mixtral-8x7B-v0.1"},
			"gpt-4":    {License: "Proprietary (OpenAI)"},
			"o1-":      {License: "Proprietary (OpenAI)"},
			"claude-3": {License: "Proprietary (Anthropic)"},
			"gemini":   {License: "Proprietary (Google)"},
		}
	} else {
		if err := json.Unmarshal(licFile, &modelLicenseMap); err != nil {
			log.Printf("Error parsing licenses.json: %v. Using defaults.", err)
		}
	}
}

func main() {
	// Headless CLI Mode for CI/CD Pipelines
	if len(os.Args) > 1 && os.Args[1] == "--cli" {
		scanDir := "."
		if len(os.Args) > 2 {
			scanDir = os.Args[2]
		}
		fmt.Printf("Running AIcap in CI/CD CLI mode on directory: %s\n", scanDir)
		bom := performScan(scanDir)

		// Pull exact repository and commit data from GitHub Actions environment
		if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
			bom.ProjectName = repo
		}
		if sha := os.Getenv("GITHUB_SHA"); sha != "" {
			bom.CommitSha = sha
		}

		bomJSON, _ := json.MarshalIndent(bom, "", "  ")

		// Check for --cyclonedx output flag
		wantCycloneDX := false
		for _, arg := range os.Args {
			if arg == "--cyclonedx" {
				wantCycloneDX = true
			}
		}

		if wantCycloneDX {
			cdx := generateCycloneDXBOM(bom)
			cdxJSON, _ := json.MarshalIndent(cdx, "", "  ")
			fmt.Println(string(cdxJSON))
		} else {
			fmt.Println(string(bomJSON))
		}

		// Phase 7: Sync to SaaS if Pro API Key is present
		apiKey := os.Getenv("AICAP_API_KEY")

		if apiKey != "" {
			fmt.Println("\n[+] Pro API Key detected. Syncing AI-BOM and Proof Drill to AIcap Cloud...")
			req, err := http.NewRequest("POST", "https://aicap.onrender.com/api/save-proof", bytes.NewBuffer(bomJSON))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+apiKey)
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil || resp.StatusCode != 201 {
					fmt.Println("[-] Warning: Failed to sync with AIcap Cloud (Is the server reachable?).")
				} else {
					fmt.Println("[+] Successfully synced Immutable Proof Drill to your dashboard!")
				}
			}
		}

		if bom.Compliance != "Passed" {
			fmt.Println("\n[!] Compliance scan failed. High-risk dependencies detected without active mitigation. Blocking pipeline.")
			os.Exit(1)
		}
		fmt.Println("\n[+] Compliance scan passed. Pipeline approved.")
		os.Exit(0)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Println("Starting Continuous AI-BOM Server on :" + port + "...")

	// Connect to Supabase
	dbURL := os.Getenv("SUPABASE_DB_URL")
	if dbURL != "" {
		isCloudSaaS = true
		var err error
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("Error opening database: %v", err)
		}
		if err = db.Ping(); err != nil {
			log.Fatalf("Error connecting to database: %v", err)
		}
		fmt.Println("Connected to Supabase PostgreSQL successfully!")
	} else {
		// In a real cloud environment, a missing DB URL for the backend is an error.
		// For local dev, we allow it for the local UI, but cloud functionality needs it.
		if os.Getenv("RENDER") == "true" || os.Getenv("VERCEL") == "true" { // Render/Vercel specific env vars
			log.Fatal("Error: SUPABASE_DB_URL is not set in cloud environment. Database connection required for SaaS features.")
		}
		fmt.Println("Warning: SUPABASE_DB_URL not set. Running in memory only.")
		db = nil // Ensure db is nil if no URL is set
	}

	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		// Enable CORS for local React dev server
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		// Run the scan
		bom := performScan(".")
		json.NewEncoder(w).Encode(bom)
	})

	// New endpoint to check or configure the Database Connection dynamically
	http.HandleFunc("/api/db-config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
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
	http.HandleFunc("/api/save-proof", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			return
		}

		if db == nil {
			http.Error(w, "Database not configured", http.StatusInternalServerError)
			return
		}

		// Phase 7: API Key Authentication for Cloud SaaS
		if isCloudSaaS {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized: Missing or malformed API Key", http.StatusUnauthorized)
				return
			}
			apiKey := strings.TrimPrefix(authHeader, "Bearer ")
			var userID string
			err := db.QueryRow("SELECT user_id FROM api_keys WHERE token = $1", apiKey).Scan(&userID)
			if err != nil {
				http.Error(w, "Unauthorized: Invalid API Key", http.StatusUnauthorized)
				return
			}
		}

		var bom AIBOM
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
		annexIVMarkdown := generateAnnexIVMarkdown(bom)

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
	http.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
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

		var records []ProofRecord
		for rows.Next() {
			var rec ProofRecord
			rows.Scan(&rec.ProjectName, &rec.CommitSha, &rec.CryptoHash, &rec.Timestamp)
			records = append(records, rec)
		}

		json.NewEncoder(w).Encode(records)
	})

	// New endpoint to fetch a specific historical proof drill markdown
	http.HandleFunc("/api/proof", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
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
	http.HandleFunc("/api/create-checkout-session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
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
	http.HandleFunc("/api/stripe-webhook", func(w http.ResponseWriter, r *http.Request) {
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
							"INSERT INTO api_keys (user_id, token, stripe_customer_id) VALUES ($1, $2, $3)",
							userID, apiKey, checkoutSession.Customer.ID,
						)
						if insertErr != nil {
							log.Printf("Failed to provision API key for user %s: %v", userID, insertErr)
						} else {
							log.Printf("API key provisioned for user %s", userID)
						}
					}
				} else {
					log.Printf("User %s already has an API key, skipping provisioning", userID)
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
	http.HandleFunc("/api/generate-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
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

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// generateAnnexIVMarkdown creates a dynamic markdown template based on the AI-BOM
func generateAnnexIVMarkdown(bom AIBOM) string {
	var sb strings.Builder
	sb.WriteString("# EU AI Act - Annex IV Technical Documentation\n\n")
	sb.WriteString(fmt.Sprintf("*Generated: %s*\n\n", time.Now().UTC().Format(time.RFC3339)))

	// Section 1: General Description
	sb.WriteString("## 1. General System Description (Annex IV, Section 1)\n")
	sb.WriteString(fmt.Sprintf("- **System Name:** %s\n", bom.ProjectName))
	sb.WriteString(fmt.Sprintf("- **Version / Commit SHA:** `%s`\n", bom.CommitSha))
	sb.WriteString(fmt.Sprintf("- **Total Files Scanned:** %d\n", bom.ScannedFiles))
	sb.WriteString(fmt.Sprintf("- **AI Components Detected:** %d\n", len(bom.Dependencies)))
	sb.WriteString("- **Intended Purpose:** `[REQUIRES MANUAL INPUT: Describe the exact purpose of this AI system]`\n\n")

	// Section 2: Architecture & Components
	sb.WriteString("## 2. System Architecture & Components (Annex IV, Section 2)\n\n")

	// 2(a): Dependencies grouped by ecosystem
	sb.WriteString("### 2(a) Pre-trained Systems & Dependencies (AI-BOM)\n")
	if len(bom.Dependencies) == 0 {
		sb.WriteString("No AI dependencies detected.\n\n")
	} else {
		// Group dependencies by ecosystem for clarity
		ecosystems := map[string][]AIDependency{}
		for _, dep := range bom.Dependencies {
			ecosystems[dep.Ecosystem] = append(ecosystems[dep.Ecosystem], dep)
		}
		for ecosystem, deps := range ecosystems {
			sb.WriteString(fmt.Sprintf("\n**%s:**\n", ecosystem))
			for _, dep := range deps {
				licenseText := ""
				if dep.License != "" {
					licenseText = fmt.Sprintf(" [License: %s]", dep.License)
				}
				sb.WriteString(fmt.Sprintf("- **%s** (v%s)%s: %s (Risk: %s)\n", dep.Name, dep.Version, licenseText, dep.Description, dep.RiskLevel))
			}
		}
		sb.WriteString("\n")
	}

	// 2(b): Licensing Summary (auto-generated)
	sb.WriteString("### 2(b) Licensing Compliance Summary\n")
	licensedCount := 0
	unlicensedHighRisk := 0
	licenseTypes := map[string]int{}
	for _, dep := range bom.Dependencies {
		if dep.License != "" {
			licensedCount++
			licenseTypes[dep.License]++
		} else if dep.RiskLevel == "High" {
			unlicensedHighRisk++
		}
	}
	sb.WriteString(fmt.Sprintf("- **Components with license data:** %d / %d\n", licensedCount, len(bom.Dependencies)))
	sb.WriteString(fmt.Sprintf("- **High-risk components missing license:** %d\n", unlicensedHighRisk))
	if len(licenseTypes) > 0 {
		sb.WriteString("- **License distribution:**\n")
		for lic, count := range licenseTypes {
			sb.WriteString(fmt.Sprintf("  - %s: %d component(s)\n", lic, count))
		}
	}
	sb.WriteString("\n")

	// 2(c): Hardware & Infrastructure
	sb.WriteString("### 2(c) Hardware Requirements & Deployment (FinOps Telemetry)\n")
	if len(bom.FinOps) == 0 {
		sb.WriteString("No specific hardware constraints or GPU requests detected in infrastructure manifests.\n\n")
	} else {
		for _, fin := range bom.FinOps {
			sb.WriteString(fmt.Sprintf("- **Resource:** %s\n", fin.Resource))
			sb.WriteString(fmt.Sprintf("  - **Finding:** %s\n", fin.Description))
			sb.WriteString(fmt.Sprintf("  - **Severity:** %s\n", fin.Severity))
		}
		sb.WriteString("\n")
	}

	// Section 3: Risk Management
	sb.WriteString("## 3. Continuous Risk Management (Article 9 & Annex IV, Section 4)\n")
	sb.WriteString(fmt.Sprintf("**Current Automated Posture:** %s\n\n", bom.Compliance))

	// Auto-generated risk register
	sb.WriteString("### 3(a) Automated Risk Register\n")
	highRiskDeps := []AIDependency{}
	secretFindings := []AIDependency{}
	for _, dep := range bom.Dependencies {
		if dep.RiskLevel == "High" && dep.Name != "Exposed Secret" {
			highRiskDeps = append(highRiskDeps, dep)
		}
		if dep.Name == "Exposed Secret" {
			secretFindings = append(secretFindings, dep)
		}
	}

	if len(highRiskDeps) > 0 {
		sb.WriteString("\n| Component | Risk | Location | Mitigation |\n")
		sb.WriteString("|---|---|---|---|\n")
		for _, dep := range highRiskDeps {
			sb.WriteString(fmt.Sprintf("| %s (v%s) | %s | %s | `[REQUIRES INPUT]` |\n", dep.Name, dep.Version, dep.RiskLevel, dep.Location))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("No high-risk AI components detected.\n\n")
	}

	if len(secretFindings) > 0 {
		sb.WriteString(fmt.Sprintf("⚠️ **CRITICAL:** %d exposed secret(s) detected in source code. Immediate remediation required.\n\n", len(secretFindings)))
	}

	// 3(b): Policy compliance
	sb.WriteString("### 3(b) Policy-as-Code Compliance\n")
	if len(bom.PolicyViolations) == 0 {
		sb.WriteString("- [x] No policy violations detected")
		sb.WriteString(" (or no `.aicap.yml` policy file configured)\n\n")
	} else {
		blockers := 0
		warnings := 0
		for _, v := range bom.PolicyViolations {
			if v.Severity == "Blocker" {
				blockers++
			} else {
				warnings++
			}
		}
		sb.WriteString(fmt.Sprintf("- **Blockers:** %d\n", blockers))
		sb.WriteString(fmt.Sprintf("- **Warnings:** %d\n\n", warnings))
		for _, v := range bom.PolicyViolations {
			icon := "⚠️"
			if v.Severity == "Blocker" {
				icon = "🚫"
			}
			sb.WriteString(fmt.Sprintf("- %s [%s] %s (%s)\n", icon, v.Rule, v.Description, v.Location))
		}
		sb.WriteString("\n")
	}

	// CI/CD controls
	sb.WriteString("### 3(c) Automated CI/CD Pipeline Controls\n")
	if bom.Compliance == "Passed" {
		sb.WriteString("- [x] High-risk dependency constraints validated.\n")
	} else {
		sb.WriteString("- [ ] **BLOCKER:** High-risk AI dependencies detected without explicit mitigation.\n")
	}
	sb.WriteString("- [ ] `[REQUIRES MANUAL INPUT: Detail prompt injection mitigation strategy]`\n\n")

	// Section 4: Human Oversight
	sb.WriteString("## 4. Human Oversight & Data Governance (Annex IV, Section 3)\n")
	sb.WriteString("- **Human-in-the-loop (HITL) Controls:** `[REQUIRES MANUAL INPUT]`\n")
	sb.WriteString("- **Training Data Provenance:** `[REQUIRES MANUAL INPUT]`\n")
	sb.WriteString("- **Bias Monitoring:** `[REQUIRES MANUAL INPUT]`\n\n")

	// Section 5: Proof Drill
	sb.WriteString("## 5. Immutable Compliance Proof (AIcap Proof Drill)\n")
	sb.WriteString("This document was generated by **AIcap** — an automated AI compliance scanner.\n")
	sb.WriteString("The AI-BOM, this Annex IV template, and the commit SHA have been cryptographically\n")
	sb.WriteString("hashed together to create an immutable audit trail.\n\n")
	sb.WriteString(fmt.Sprintf("- **Commit SHA:** `%s`\n", bom.CommitSha))
	sb.WriteString(fmt.Sprintf("- **Scan Timestamp:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("- **Cryptographic proof hash available in the AIcap Cloud dashboard.**\n")

	return sb.String()
}

// CycloneDX SBOM structures — minimal CycloneDX 1.5 compatible output
type CycloneDXBOM struct {
	BOMFormat    string              `json:"bomFormat"`
	SpecVersion  string              `json:"specVersion"`
	SerialNumber string              `json:"serialNumber"`
	Version      int                 `json:"version"`
	Metadata     CycloneDXMetadata   `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

type CycloneDXMetadata struct {
	Timestamp string              `json:"timestamp"`
	Component CycloneDXComponent  `json:"component"`
}

type CycloneDXComponent struct {
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	Purl       string              `json:"purl,omitempty"`
	Licenses   []CycloneDXLicense  `json:"licenses,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

type CycloneDXLicense struct {
	License struct {
		Name string `json:"name"`
	} `json:"license"`
}

type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HFModelResponse maps the JSON response from the Hugging Face API
type HFModelResponse struct {
	Tags []string `json:"tags"`
}

// performScan encapsulates the core scanning logic
func performScan(scanDir string) AIBOM {
	bom := AIBOM{
		ProjectName:  filepath.Base(scanDir),
		Dependencies: []AIDependency{},
		FinOps:       []FinOpsFinding{},
		Compliance:   "Pending",
	}

	// Walk the directory looking for manifest files
	err := filepath.Walk(scanDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories like .git
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") && info.Name() != "." && info.Name() != ".." {
			return filepath.SkipDir
		}

		if !info.IsDir() {
			bom.ScannedFiles++
			if info.Name() == "requirements.txt" {
				deps := parseRequirementsTxt(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "package.json" {
				deps := parsePackageJson(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "go.mod" {
				deps := parseGoMod(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "pyproject.toml" {
				deps := parsePyProjectToml(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if info.Name() == "Dockerfile" || strings.HasPrefix(info.Name(), "Dockerfile.") {
				deps := parseDockerfile(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if strings.HasSuffix(info.Name(), ".go") {
				deps := parseGoAST(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}
			if strings.HasSuffix(info.Name(), ".py") {
				deps := parsePythonSource(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}

			// Scan .env files for leaked secrets
			if info.Name() == ".env" || strings.HasSuffix(info.Name(), ".env") {
				deps := parseEnvFile(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}

			ext := strings.ToLower(filepath.Ext(info.Name()))
			isModelWeight := false
			switch ext {
			case ".safetensors", ".onnx", ".pt", ".h5", ".gguf", ".bin", ".tflite", ".pb", ".mlmodel", ".ckpt":
				isModelWeight = true
			}

			// Some models are directories containing .bin or .safetensors. We just flag the file.
			if info.Name() == "pytorch_model.bin" || info.Name() == "model.safetensors" {
				isModelWeight = true
			}

			if isModelWeight {
				deps := parseLocalModelWeight(path)
				bom.Dependencies = append(bom.Dependencies, deps...)
			}

			if ext == ".yaml" || ext == ".yml" {
				finops := parseKubernetesManifest(path)
				bom.FinOps = append(bom.FinOps, finops...)
				// Also check for Helm values with GPU resources
				if info.Name() == "values.yaml" || info.Name() == "values.yml" {
					helmFinOps := parseHelmValues(path)
					bom.FinOps = append(bom.FinOps, helmFinOps...)
				}
			}

			// Terraform FinOps: parse .tf files for GPU instance types
			if ext == ".tf" {
				finops := parseTerraformFile(path)
				bom.FinOps = append(bom.FinOps, finops...)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Error scanning directory: %v", err)
	}

	// Determine overall compliance posture based on findings
	bom.Compliance = "Passed"
	for i, dep := range bom.Dependencies {
		if dep.RiskLevel == "High" {
			bom.Compliance = "Action Required (Annex IV Documentation Missing)"
		}

		// Phase 2, Layer 3: Enrich models with License data via Hugging Face API
		if dep.Name == "Hardcoded Model" || strings.HasPrefix(dep.Ecosystem, "Model Weight") {
			hfID := ""
			val := strings.ToLower(dep.Version)
			if dep.Version == "local" {
				val = strings.ToLower(dep.Name)
			}

			// Heuristic mapping to Hugging Face registries or proprietary licenses
			for key, mapping := range modelLicenseMap {
				if strings.Contains(val, key) {
					if mapping.License != "" {
						bom.Dependencies[i].License = mapping.License
					} else if mapping.HFID != "" {
						hfID = mapping.HFID
					}
					break
				}
			}

			if hfID != "" {
				license := fetchHuggingFaceMetadata(hfID)
				if license != "" {
					bom.Dependencies[i].License = license
				}
			}
		}
	}
	// Phase: OWASP ML Top 10 Risk Enrichment
	// Cross-reference detected dependencies with known ML attack vectors
	enrichWithOWASPRisks(&bom)

	// Phase: Policy-as-Code Evaluation
	// Load .aicap.yml policy if it exists in the scanned directory
	policy := loadPolicyConfig(scanDir)
	if policy != nil {
		bom.PolicyViolations = evaluatePolicy(policy, bom)
		if len(bom.PolicyViolations) > 0 {
			for _, v := range bom.PolicyViolations {
				if v.Severity == "Blocker" {
					bom.Compliance = "Blocked by Policy"
					break
				}
			}
		}
	}

	return bom
}

// loadPolicyConfig reads a .aicap.yml policy configuration file
func loadPolicyConfig(scanDir string) *PolicyConfig {
	policyPath := filepath.Join(scanDir, ".aicap.yml")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil // No policy file — that's okay
	}

	policy := &PolicyConfig{}

	// Simple YAML-like parser for our specific format (avoids yaml dependency)
	lines := strings.Split(string(data), "\n")
	var currentList *[]string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Handle list items
		if strings.HasPrefix(trimmed, "- ") && currentList != nil {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = strings.Trim(item, "\"'")
			*currentList = append(*currentList, item)
			continue
		}

		// Handle key-value pairs
		if strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, "\"'")
			currentList = nil

			switch key {
			case "allowed_models":
				currentList = &policy.AllowedModels
			case "blocked_models":
				currentList = &policy.BlockedModels
			case "allowed_licenses":
				currentList = &policy.AllowedLicenses
			case "max_risk_level":
				policy.MaxRiskLevel = val
			case "block_on_high_risk":
				policy.BlockOnHighRisk = val == "true"
			case "require_licenses":
				policy.RequireLicenses = val == "true"
			}
		}
	}

	return policy
}

// evaluatePolicy checks detected dependencies against the policy configuration
func evaluatePolicy(policy *PolicyConfig, bom AIBOM) []PolicyViolation {
	var violations []PolicyViolation

	for _, dep := range bom.Dependencies {
		depNameLower := strings.ToLower(dep.Name)
		depVersionLower := strings.ToLower(dep.Version)

		// Check blocked models
		for _, blocked := range policy.BlockedModels {
			blockedLower := strings.ToLower(blocked)
			if strings.Contains(depNameLower, blockedLower) || strings.Contains(depVersionLower, blockedLower) {
				violations = append(violations, PolicyViolation{
					Rule:        "blocked_model",
					Severity:    "Blocker",
					Description: fmt.Sprintf("Model '%s' is explicitly blocked by .aicap.yml policy", dep.Version),
					Location:    dep.Location,
				})
			}
		}

		// Check allowed models (if allowlist is specified, anything not in it is blocked)
		if len(policy.AllowedModels) > 0 && (dep.Name == "Hardcoded Model" || strings.HasPrefix(dep.Ecosystem, "Model Weight")) {
			isAllowed := false
			for _, allowed := range policy.AllowedModels {
				allowedLower := strings.ToLower(allowed)
				if strings.Contains(depVersionLower, allowedLower) || strings.Contains(depNameLower, allowedLower) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				violations = append(violations, PolicyViolation{
					Rule:        "allowed_model_violation",
					Severity:    "Blocker",
					Description: fmt.Sprintf("Model '%s' is not in the approved model allowlist defined in .aicap.yml", dep.Version),
					Location:    dep.Location,
				})
			}
		}

		// Check risk level threshold
		if policy.BlockOnHighRisk && dep.RiskLevel == "High" {
			violations = append(violations, PolicyViolation{
				Rule:        "high_risk_blocked",
				Severity:    "Blocker",
				Description: fmt.Sprintf("High-risk dependency '%s' blocked by policy (block_on_high_risk: true)", dep.Name),
				Location:    dep.Location,
			})
		}

		// Check license requirements
		if policy.RequireLicenses && dep.License == "" && dep.RiskLevel == "High" {
			violations = append(violations, PolicyViolation{
				Rule:        "missing_license",
				Severity:    "Warning",
				Description: fmt.Sprintf("High-risk dependency '%s' has no license information. Policy requires licenses for all high-risk components.", dep.Name),
				Location:    dep.Location,
			})
		}

		// Check allowed licenses
		if len(policy.AllowedLicenses) > 0 && dep.License != "" {
			isAllowed := false
			for _, allowedLic := range policy.AllowedLicenses {
				if strings.EqualFold(dep.License, allowedLic) {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				violations = append(violations, PolicyViolation{
					Rule:        "license_not_allowed",
					Severity:    "Warning",
					Description: fmt.Sprintf("License '%s' for '%s' is not in the approved license list", dep.License, dep.Name),
					Location:    dep.Location,
				})
			}
		}
	}

	return violations
}

// parseRequirementsTxt parses Python dependencies
func parseRequirementsTxt(filePath string) []AIDependency {
	var found []AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Regex to match "library==version" or just "library"
	re := regexp.MustCompile(`^([a-zA-Z0-9_\-]+)(?:[>=<~]+([a-zA-Z0-9_\-\.]+))?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			pkgName := strings.ToLower(matches[1])
			version := "unknown"
			if len(matches) > 2 && matches[2] != "" {
				version = matches[2]
			}

			if meta, exists := targetAILibraries[pkgName]; exists {
				found = append(found, AIDependency{
					Name:        pkgName,
					Version:     version,
					Ecosystem:   "Python (pip)",
					RiskLevel:   meta.Risk,
					Description: meta.Desc,
					Location:    filePath,
				})
			}
		}
	}
	return found
}

// fetchHuggingFaceMetadata makes a live API call to retrieve model licenses
func fetchHuggingFaceMetadata(modelID string) string {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://huggingface.co/api/models/" + modelID)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var hfResp HFModelResponse
	if err := json.NewDecoder(resp.Body).Decode(&hfResp); err != nil {
		return ""
	}
	for _, tag := range hfResp.Tags {
		if strings.HasPrefix(tag, "license:") {
			return strings.TrimPrefix(tag, "license:")
		}
	}
	return ""
}

// parseLocalModelWeight handles local ML serialization formats
func parseLocalModelWeight(filePath string) []AIDependency {
	return []AIDependency{
		{
			Name:        filepath.Base(filePath),
			Version:     "local",
			Ecosystem:   "Model Weight (" + filepath.Ext(filePath) + ")",
			RiskLevel:   "High",
			Description: "Locally hosted model weight file detected",
			Location:    filePath,
		},
	}
}

// parsePackageJson parses Node.js dependencies
func parsePackageJson(filePath string) []AIDependency {
	var found []AIDependency
	file, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(file, &pkg); err != nil {
		return found
	}

	checkDeps := func(deps map[string]string) {
		for name, version := range deps {
			cleanName := strings.ToLower(name)
			if meta, exists := targetAILibraries[cleanName]; exists {
				found = append(found, AIDependency{
					Name:        name,
					Version:     strings.TrimPrefix(strings.TrimPrefix(version, "^"), "~"),
					Ecosystem:   "Node.js (npm)",
					RiskLevel:   meta.Risk,
					Description: meta.Desc,
					Location:    filePath,
				})
			}
		}
	}

	checkDeps(pkg.Dependencies)
	checkDeps(pkg.DevDependencies)

	return found
}

// parsePythonSource uses heuristic regex matching to find string literals AND import statements in Python files
func parsePythonSource(filePath string) []AIDependency {
	var found []AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Regex to match string literals inside single or double quotes
	strRegex := regexp.MustCompile(`"([^"]*)"|'([^']*)'`)
	// Regex to match "import X" or "from X import Y" patterns
	importRegex := regexp.MustCompile(`^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+([a-zA-Z0-9_]+)(?:\.[a-zA-Z0-9_.]+)?\s+import)`)

	detectedImports := map[string]bool{} // deduplicate
	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()

		// Detect Python import statements for AI libraries
		importMatches := importRegex.FindStringSubmatch(line)
		if len(importMatches) > 0 {
			modName := importMatches[1]
			if modName == "" {
				modName = importMatches[2]
			}
			modName = strings.ToLower(modName)
			if meta, exists := targetAILibraries[modName]; exists && !detectedImports[modName] {
				detectedImports[modName] = true
				found = append(found, AIDependency{
					Name:        modName,
					Version:     "imported",
					Ecosystem:   "Source Code (.py import)",
					RiskLevel:   meta.Risk,
					Description: meta.Desc + " (detected via import statement)",
					Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
				})
			}
		}

		// Detect hardcoded model strings and secrets
		matches := strRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 2 {
				val := match[1]
				if val == "" {
					val = match[2]
				}

				isTargetModel := false
				for _, model := range targetModels {
					if strings.Contains(val, model) {
						isTargetModel = true
						break
					}
				}

				if isTargetModel {
					found = append(found, AIDependency{
						Name:        "Hardcoded Model",
						Version:     val,
						Ecosystem:   "Source Code (.py)",
						RiskLevel:   "High",
						Description: "Hardcoded AI model identifier found in Python source code",
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
				}

				if strings.HasPrefix(val, "sk-") && len(val) > 20 {
					found = append(found, AIDependency{
						Name:        "Exposed Secret",
						Version:     "HIDDEN",
						Ecosystem:   "Source Code (.py)",
						RiskLevel:   "High",
						Description: "Potential hardcoded API key found in Python source code",
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
				}
			}
		}
		lineNum++
	}
	return found
}

// parseKubernetesManifest checks IaC files for expensive GPU requests without optimization
func parseKubernetesManifest(filePath string) []FinOpsFinding {
	var found []FinOpsFinding
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	hasGPURequest := false
	hasOptimization := false

	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		// Look for common GPU resource requests
		if strings.Contains(line, "nvidia.com/gpu") || strings.Contains(line, "amd.com/gpu") {
			hasGPURequest = true
		}
		// Look for indicators of Multi-Instance GPU (MIG) or time-slicing
		if strings.Contains(line, "mig.config") || strings.Contains(line, "time-slicing") {
			hasOptimization = true
		}
	}

	if hasGPURequest && !hasOptimization {
		found = append(found, FinOpsFinding{
			Resource:    filepath.Base(filePath),
			Severity:    "Warning",
			Description: "Expensive GPU requested without MIG or time-slicing configuration. Potential cost inefficiency.",
			Location:    filePath,
		})
	}

	return found
}

// parseGoAST utilizes Go's Abstract Syntax Tree to find hardcoded models and secrets
func parseGoAST(filePath string) []AIDependency {
	var found []AIDependency
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		return found
	}

	ast.Inspect(node, func(n ast.Node) bool {
		// Look specifically for literal values (e.g., strings) to avoid matching comments or variable names
		lit, ok := n.(*ast.BasicLit)
		if ok && lit.Kind == token.STRING {
			val := strings.Trim(lit.Value, "\"")

			isTargetModel := false
			for _, model := range targetModels {
				if strings.Contains(val, model) {
					isTargetModel = true
					break
				}
			}

			// Detect hardcoded model identifiers
			if isTargetModel {
				pos := fset.Position(lit.Pos())
				found = append(found, AIDependency{
					Name:        "Hardcoded Model",
					Version:     val,
					Ecosystem:   "Source Code (.go)",
					RiskLevel:   "High",
					Description: "Hardcoded AI model identifier found in source code",
					Location:    pos.String(),
				})
			}

			// Detect exposed API Keys (Basic heuristic for OpenAI/Anthropic keys)
			if strings.HasPrefix(val, "sk-") && len(val) > 20 {
				pos := fset.Position(lit.Pos())
				found = append(found, AIDependency{
					Name:        "Exposed Secret",
					Version:     "HIDDEN",
					Ecosystem:   "Source Code (.go)",
					RiskLevel:   "High",
					Description: "Potential hardcoded API key found in source code",
					Location:    pos.String(),
				})
			}
		}
		return true
	})

	return found
}

// parseGoMod extracts AI dependencies from Go module files
func parseGoMod(filePath string) []AIDependency {
	var found []AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRequireBlock := false
	// Match lines like: github.com/sashabaranov/go-openai v1.20.0
	requireLineRe := regexp.MustCompile(`^\s*([^\s]+)\s+v?([^\s]+)`)

	// Known AI-related Go packages mapped to our library metadata
	goAIModules := map[string]string{
		"go-openai":          "openai",
		"anthropic-sdk-go":   "anthropic",
		"generative-ai-go":  "google-generativeai",
		"langchaingo":       "langchain",
		"ollama":            "ollama",
		"go-cohere":         "cohere",
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if line == ")" && inRequireBlock {
			inRequireBlock = false
			continue
		}

		// Handle single-line require: require github.com/foo/bar v1.0.0
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			line = strings.TrimPrefix(line, "require ")
			inRequireBlock = false // it's a one-liner
		} else if !inRequireBlock {
			continue
		}

		matches := requireLineRe.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}

		modulePath := strings.ToLower(matches[1])
		version := matches[2]

		// Check if any known AI Go module name appears in the module path
		for goModKey, libKey := range goAIModules {
			if strings.Contains(modulePath, goModKey) {
				meta, exists := targetAILibraries[libKey]
				if !exists {
					meta = LibraryMeta{Risk: "Medium", Desc: "AI-related Go module"}
				}
				found = append(found, AIDependency{
					Name:        modulePath,
					Version:     version,
					Ecosystem:   "Go (module)",
					RiskLevel:   meta.Risk,
					Description: meta.Desc,
					Location:    filePath,
				})
				break
			}
		}
	}
	return found
}

// parsePyProjectToml extracts AI dependencies from Poetry pyproject.toml files
func parsePyProjectToml(filePath string) []AIDependency {
	var found []AIDependency
	data, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	inDepsSection := false

	// Match lines like: openai = "^1.12.0" or torch = {version = ">=2.0"}
	depLineRe := regexp.MustCompile(`^\s*([a-zA-Z0-9_-]+)\s*=\s*(.+)`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect dependency sections
		if trimmed == "[tool.poetry.dependencies]" || trimmed == "[project.dependencies]" {
			inDepsSection = true
			continue
		}

		// Exit when we hit a new section
		if strings.HasPrefix(trimmed, "[") {
			inDepsSection = false
			continue
		}

		if !inDepsSection {
			continue
		}

		matches := depLineRe.FindStringSubmatch(trimmed)
		if len(matches) < 3 {
			continue
		}

		pkgName := strings.ToLower(matches[1])
		versionSpec := matches[2]

		// Skip non-dependency keys like "python"
		if pkgName == "python" {
			continue
		}

		// Extract version string — handles "^1.0", {version = ">=2.0"}, etc.
		version := "unknown"
		versionSpec = strings.Trim(versionSpec, " \"'")
		if strings.HasPrefix(versionSpec, "{") {
			// Complex version specifier: extract version value
			vRe := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
			vMatch := vRe.FindStringSubmatch(versionSpec)
			if len(vMatch) > 1 {
				version = vMatch[1]
			}
		} else {
			version = strings.TrimLeft(versionSpec, "^~>=<!")
		}

		if meta, exists := targetAILibraries[pkgName]; exists {
			found = append(found, AIDependency{
				Name:        pkgName,
				Version:     version,
				Ecosystem:   "Python (Poetry/PEP)",
				RiskLevel:   meta.Risk,
				Description: meta.Desc,
				Location:    filePath,
			})
		}
	}
	return found
}

// parseDockerfile analyzes Dockerfiles to detect AI framework base images and model weight copies
func parseDockerfile(filePath string) []AIDependency {
	var found []AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	// Known AI-related Docker base images
	aiBaseImages := map[string]string{
		"pytorch":       "PyTorch Container Image",
		"tensorflow":    "TensorFlow Container Image",
		"nvidia/cuda":   "NVIDIA CUDA Base Image",
		"huggingface":   "Hugging Face Container Image",
		"nvcr.io":       "NVIDIA Container Registry Image",
		"ollama":        "Ollama Container Image",
		"vllm":          "vLLM Inference Engine Image",
		"tritonserver":  "NVIDIA Triton Inference Server",
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		lineLower := strings.ToLower(line)

		// Detect FROM instructions with AI base images
		if strings.HasPrefix(lineLower, "from ") {
			imageParts := strings.Fields(line)
			if len(imageParts) >= 2 {
				imageName := strings.ToLower(imageParts[1])
				for aiKey, aiDesc := range aiBaseImages {
					if strings.Contains(imageName, aiKey) {
						found = append(found, AIDependency{
							Name:        imageParts[1],
							Version:     "docker-image",
							Ecosystem:   "Container Image (Dockerfile)",
							RiskLevel:   "High",
							Description: aiDesc + " detected as base image",
							Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
						})
						break
					}
				}
			}
		}

		// Detect COPY/ADD of model weight files
		if strings.HasPrefix(lineLower, "copy ") || strings.HasPrefix(lineLower, "add ") {
			modelExtensions := []string{".safetensors", ".onnx", ".pt", ".h5", ".gguf", ".bin", ".tflite", ".pb", ".ckpt"}
			for _, ext := range modelExtensions {
				if strings.Contains(lineLower, ext) {
					found = append(found, AIDependency{
						Name:        "Containerized Model Weight",
						Version:     "docker-layer",
						Ecosystem:   "Container Image (Dockerfile)",
						RiskLevel:   "High",
						Description: fmt.Sprintf("Model weight file (%s) being copied into container image", ext),
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
					break
				}
			}
		}

		// Detect pip install of AI libraries within Dockerfile RUN commands
		if strings.HasPrefix(lineLower, "run ") && strings.Contains(lineLower, "pip install") {
			for libName, meta := range targetAILibraries {
				if strings.Contains(lineLower, libName) {
					found = append(found, AIDependency{
						Name:        libName,
						Version:     "docker-install",
						Ecosystem:   "Container Image (pip in Dockerfile)",
						RiskLevel:   meta.Risk,
						Description: meta.Desc + " (installed in Dockerfile)",
						Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
					})
				}
			}
		}
	}
	return found
}

// generateCycloneDXBOM converts AIcap's AIBOM to CycloneDX 1.5 JSON format
func generateCycloneDXBOM(bom AIBOM) CycloneDXBOM {
	components := []CycloneDXComponent{}

	for _, dep := range bom.Dependencies {
		comp := CycloneDXComponent{
			Type:    classifyComponentType(dep),
			Name:    dep.Name,
			Version: dep.Version,
			Purl:    generatePURL(dep),
			Properties: []CycloneDXProperty{
				{Name: "aicap:riskLevel", Value: dep.RiskLevel},
				{Name: "aicap:ecosystem", Value: dep.Ecosystem},
				{Name: "aicap:description", Value: dep.Description},
			},
		}

		if dep.Location != "" {
			comp.Properties = append(comp.Properties, CycloneDXProperty{
				Name: "aicap:location", Value: dep.Location,
			})
		}

		if dep.License != "" {
			lic := CycloneDXLicense{}
			lic.License.Name = dep.License
			comp.Licenses = []CycloneDXLicense{lic}
		}

		components = append(components, comp)
	}

	return CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + fmt.Sprintf("%x", sha256.Sum256([]byte(bom.ProjectName+bom.CommitSha)))[:36],
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: CycloneDXComponent{
				Type:    "application",
				Name:    bom.ProjectName,
				Version: bom.CommitSha,
			},
		},
		Components: components,
	}
}

// classifyComponentType maps AIcap dependency types to CycloneDX component types
func classifyComponentType(dep AIDependency) string {
	if strings.HasPrefix(dep.Ecosystem, "Model Weight") || strings.HasPrefix(dep.Ecosystem, "Container Image") {
		return "machine-learning-model"
	}
	if dep.Name == "Exposed Secret" {
		return "data"
	}
	return "library"
}

// generatePURL creates a Package URL for the dependency
func generatePURL(dep AIDependency) string {
	switch {
	case strings.Contains(dep.Ecosystem, "pip") || strings.Contains(dep.Ecosystem, "Poetry"):
		return fmt.Sprintf("pkg:pypi/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "npm"):
		return fmt.Sprintf("pkg:npm/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "Go"):
		return fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version)
	case strings.Contains(dep.Ecosystem, "Dockerfile"):
		return fmt.Sprintf("pkg:docker/%s", dep.Name)
	default:
		return ""
	}
}

// parseTerraformFile analyzes .tf files for GPU instance types and cost optimization opportunities
func parseTerraformFile(filePath string) []FinOpsFinding {
	var found []FinOpsFinding
	data, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	content := strings.ToLower(string(data))

	// AWS GPU instance families
	awsGPUInstances := map[string]string{
		"p3.":    "NVIDIA V100 GPU (p3) — $3.06-$24.48/hr",
		"p4d.":   "NVIDIA A100 GPU (p4d) — $32.77/hr",
		"p4de.":  "NVIDIA A100 80GB GPU (p4de) — $40.97/hr",
		"p5.":    "NVIDIA H100 GPU (p5) — $98.32/hr",
		"g4dn.":  "NVIDIA T4 GPU (g4dn) — $0.53-$7.82/hr",
		"g5.":    "NVIDIA A10G GPU (g5) — $1.01-$16.29/hr",
		"g5g.":   "AWS Graviton GPU (g5g) — $0.42-$2.74/hr",
		"g6.":    "NVIDIA L4 GPU (g6) — $0.80-$13.35/hr",
		"inf1.":  "AWS Inferentia (inf1) — $0.23-$4.72/hr",
		"inf2.":  "AWS Inferentia2 (inf2) — $0.76-$12.98/hr",
		"trn1.":  "AWS Trainium (trn1) — $1.34-$21.50/hr",
	}

	// Azure GPU instance families
	azureGPUInstances := map[string]string{
		"standard_nc":  "NVIDIA T4/V100 GPU (NC-series)",
		"standard_nd":  "NVIDIA A100/H100 GPU (ND-series)",
		"standard_nv":  "NVIDIA GPU for visualization (NV-series)",
	}

	// GCP GPU instance families
	gcpGPUInstances := map[string]string{
		"a2-highgpu":    "NVIDIA A100 GPU (a2-highgpu)",
		"a2-megagpu":    "NVIDIA A100 80GB GPU (a2-megagpu)",
		"g2-standard":   "NVIDIA L4 GPU (g2-standard)",
		"a3-highgpu":    "NVIDIA H100 GPU (a3-highgpu)",
	}

	checkInstances := func(instances map[string]string, cloud string) {
		for instanceType, desc := range instances {
			if strings.Contains(content, instanceType) {
				// Check for spot/preemptible configurations
				hasSpot := strings.Contains(content, "spot") ||
					strings.Contains(content, "preemptible") ||
					strings.Contains(content, "capacity_type") && strings.Contains(content, "spot")

				severity := "Warning"
				description := fmt.Sprintf("%s instance detected in Terraform config: %s.", cloud, desc)
				if !hasSpot {
					description += " Consider using spot/preemptible instances for 60-90%% cost savings on non-critical workloads."
				} else {
					severity = "Info"
					description += " Spot/preemptible pricing detected — good cost optimization."
				}

				found = append(found, FinOpsFinding{
					Resource:    filepath.Base(filePath),
					Severity:    severity,
					Description: description,
					Location:    filePath,
				})
			}
		}
	}

	checkInstances(awsGPUInstances, "AWS")
	checkInstances(azureGPUInstances, "Azure")
	checkInstances(gcpGPUInstances, "GCP")

	return found
}

// parseEnvFile scans .env files for exposed AI platform API keys and secrets
func parseEnvFile(filePath string) []AIDependency {
	var found []AIDependency
	file, err := os.Open(filePath)
	if err != nil {
		return found
	}
	defer file.Close()

	// Sensitive key patterns for AI/ML platforms
	sensitivePatterns := map[string]string{
		"sk-":                     "OpenAI API Key",
		"sk-ant-":                 "Anthropic API Key",
		"hf_":                     "Hugging Face API Token",
		"AIza":                    "Google AI API Key",
		"AKIA":                    "AWS Access Key (potential SageMaker/Bedrock)",
		"r8_":                     "Replicate API Token",
		"xai-":                    "xAI (Grok) API Key",
	}

	// Also check key names that hint at AI services
	sensitiveKeyNames := map[string]string{
		"OPENAI_API_KEY":          "OpenAI",
		"ANTHROPIC_API_KEY":       "Anthropic",
		"HUGGINGFACE_TOKEN":       "Hugging Face",
		"HF_TOKEN":                "Hugging Face",
		"GOOGLE_AI_API_KEY":       "Google AI",
		"COHERE_API_KEY":          "Cohere",
		"REPLICATE_API_TOKEN":     "Replicate",
		"AZURE_OPENAI_API_KEY":    "Azure OpenAI",
		"AWS_SECRET_ACCESS_KEY":   "AWS (SageMaker/Bedrock)",
		"WANDB_API_KEY":           "Weights & Biases",
		"LANGCHAIN_API_KEY":       "LangChain/LangSmith",
		"PINECONE_API_KEY":        "Pinecone Vector DB",
		"TOGETHER_API_KEY":        "Together AI",
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		keyName := strings.TrimSpace(parts[0])
		keyValue := strings.TrimSpace(parts[1])
		keyValue = strings.Trim(keyValue, "\"'")

		// Check if the variable name suggests an AI API key
		if platform, isAIKey := sensitiveKeyNames[strings.ToUpper(keyName)]; isAIKey {
			if keyValue != "" && keyValue != "your-key-here" && !strings.HasPrefix(keyValue, "${") && !strings.HasPrefix(keyValue, "<") {
				found = append(found, AIDependency{
					Name:        "Exposed Secret",
					Version:     "HIDDEN",
					Ecosystem:   "Environment File (.env)",
					RiskLevel:   "High",
					Description: fmt.Sprintf("%s API key found in .env file — should be in a secret manager, not committed to VCS", platform),
					Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
				})
			}
		}

		// Check if the value matches a known secret pattern
		for prefix, platform := range sensitivePatterns {
			if strings.HasPrefix(keyValue, prefix) && len(keyValue) > 20 {
				found = append(found, AIDependency{
					Name:        "Exposed Secret",
					Version:     "HIDDEN",
					Ecosystem:   "Environment File (.env)",
					RiskLevel:   "High",
					Description: fmt.Sprintf("%s detected in .env file — rotate this key immediately", platform),
					Location:    fmt.Sprintf("%s:%d", filePath, lineNum),
				})
				break // avoid double-flagging
			}
		}
	}
	return found
}

// parseHelmValues analyzes Helm values.yaml for GPU resource requests and AI model serving configs
func parseHelmValues(filePath string) []FinOpsFinding {
	var found []FinOpsFinding
	data, err := os.ReadFile(filePath)
	if err != nil {
		return found
	}

	content := strings.ToLower(string(data))
	lines := strings.Split(content, "\n")

	hasGPU := false
	hasModelServing := false
	hasAutoscaling := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect GPU resource requests
		if strings.Contains(trimmed, "nvidia.com/gpu") || strings.Contains(trimmed, "amd.com/gpu") {
			hasGPU = true
		}

		// Detect model serving frameworks
		modelServingPatterns := []string{
			"tritonserver", "tensorflow-serving", "torchserve", "seldon",
			"kserve", "mlflow", "bentoml", "ray-serve", "vllm",
		}
		for _, pattern := range modelServingPatterns {
			if strings.Contains(trimmed, pattern) {
				hasModelServing = true
			}
		}

		// Detect autoscaling configuration
		if strings.Contains(trimmed, "autoscaling") || strings.Contains(trimmed, "hpa") || strings.Contains(trimmed, "minreplicas") {
			hasAutoscaling = true
		}
	}

	if hasGPU {
		severity := "Warning"
		desc := "GPU resource requests detected in Helm values. "
		if !hasAutoscaling {
			desc += "No autoscaling configuration found — fixed GPU allocation may lead to cost waste during low-traffic periods."
		} else {
			severity = "Info"
			desc += "Autoscaling is configured — good cost optimization practice."
		}
		found = append(found, FinOpsFinding{
			Resource:    filepath.Base(filePath),
			Severity:    severity,
			Description: desc,
			Location:    filePath,
		})
	}

	if hasModelServing {
		found = append(found, FinOpsFinding{
			Resource:    filepath.Base(filePath),
			Severity:    "Info",
			Description: "AI model serving framework configuration detected in Helm values. Consider batching inference requests for GPU utilization optimization.",
			Location:    filePath,
		})
	}

	return found
}

// owaspMLRisks provides a static mapping of detected dependencies to OWASP Machine Learning Top 10 risks
// This enriches the compliance report with known attack vectors
var owaspMLRisks = map[string][]string{
	"openai":       {"ML06:2023 AI Supply Chain Attacks - External LLM API dependency creates supply chain risk"},
	"anthropic":    {"ML06:2023 AI Supply Chain Attacks - External LLM API dependency creates supply chain risk"},
	"langchain":    {"ML01:2023 Input Manipulation - LLM orchestration framework susceptible to prompt injection", "ML06:2023 AI Supply Chain Attacks - Third-party orchestration framework creates supply chain risk"},
	"torch":        {"ML04:2023 Model Theft - Local model weights may be extractable", "ML08:2023 Model Skewing - Training pipeline integrity must be verified"},
	"tensorflow":   {"ML04:2023 Model Theft - Local model weights may be extractable", "ML08:2023 Model Skewing - Training pipeline integrity must be verified"},
	"transformers": {"ML06:2023 AI Supply Chain Attacks - Pre-trained model supply chain risk", "ML02:2023 Data Poisoning - Pre-trained models may contain poisoned weights"},
	"scikit-learn": {"ML08:2023 Model Skewing - Ensure training data distributions are monitored"},
	"ollama":       {"ML04:2023 Model Theft - Local model hosting increases model exfiltration surface"},
	"chromadb":     {"ML09:2023 Output Integrity - Vector DB poisoning can corrupt RAG retrieval results"},
	"pinecone":     {"ML09:2023 Output Integrity - Vector DB poisoning can corrupt RAG retrieval results"},
}

// enrichWithOWASPRisks adds OWASP ML Top 10 risk annotations to the AIBOM
func enrichWithOWASPRisks(bom *AIBOM) {
	for i, dep := range bom.Dependencies {
		depNameLower := strings.ToLower(dep.Name)
		if risks, ok := owaspMLRisks[depNameLower]; ok {
			// Append OWASP risks to the description
			owaspNote := " | OWASP ML: " + strings.Join(risks, "; ")
			// Only add if not already annotated
			if !strings.Contains(bom.Dependencies[i].Description, "OWASP") {
				bom.Dependencies[i].Description += owaspNote
			}
		}
	}
}
