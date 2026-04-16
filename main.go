package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"aicap/pkg/api"
	"aicap/pkg/compliance"
	"aicap/pkg/migrate"
	"aicap/pkg/scanner"

	_ "github.com/lib/pq"
)

func main() {
	// --migrate runs schema migrations against SUPABASE_DB_URL and exits.
	// Intended for use as a pre-deploy step or a one-shot local command. We
	// also auto-run migrations at server boot when RUN_MIGRATIONS=true, but a
	// dedicated subcommand is useful for CI pipelines that want to fail the
	// deploy before the new binary starts taking traffic.
	if len(os.Args) > 1 && os.Args[1] == "--migrate" {
		dbURL := os.Getenv("SUPABASE_DB_URL")
		if dbURL == "" {
			log.Fatal("--migrate requires SUPABASE_DB_URL to be set")
		}
		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
		defer db.Close()
		if err := db.Ping(); err != nil {
			log.Fatalf("ping db: %v", err)
		}
		if err := migrate.Apply(db); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		fmt.Println("migrations applied")
		return
	}

	// Headless CLI Mode for CI/CD Pipelines
	if len(os.Args) > 1 && os.Args[1] == "--cli" {
		scanDir := "."
		if len(os.Args) > 2 {
			scanDir = os.Args[2]
		}
		fmt.Printf("Running AIcap in CI/CD CLI mode on directory: %s\n", scanDir)
		bom := scanner.PerformScan(scanDir)

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
			cdx := compliance.GenerateCycloneDXBOM(bom)
			cdxJSON, _ := json.MarshalIndent(cdx, "", "  ")
			fmt.Println(string(cdxJSON))
		} else {
			fmt.Println(string(bomJSON))
		}

		// Phase 7: Sync to SaaS if Pro API Key is present
		apiKey := os.Getenv("AICAP_API_KEY")

		if apiKey != "" {
			fmt.Println("\n[+] Pro API Key detected. Syncing AI-BOM and Proof Drill to AIcap Cloud...")
			apiURL := os.Getenv("AICAP_API_URL")
			if apiURL == "" {
				apiURL = "https://aicap.onrender.com/api/save-proof"
			}
			req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(bomJSON))
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

	var db *sql.DB
	isCloudSaaS := false

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

		// RUN_MIGRATIONS=true tells the server to apply any pending schema
		// migrations before it starts accepting traffic. Opt-in (not default)
		// because some deployment flows prefer a separate `aicap --migrate`
		// step in CI so a bad migration fails the pipeline rather than a
		// running pod. Safe to enable on the staging/Render setup where a
		// single instance boots on each deploy.
		if os.Getenv("RUN_MIGRATIONS") == "true" {
			if err := migrate.Apply(db); err != nil {
				log.Fatalf("Error applying migrations: %v", err)
			}
		}
	} else {
		if os.Getenv("RENDER") == "true" || os.Getenv("VERCEL") == "true" {
			log.Fatal("Error: SUPABASE_DB_URL is not set in cloud environment. Database connection required for SaaS features.")
		}
		fmt.Println("Warning: SUPABASE_DB_URL not set. Running in memory only.")
		db = nil
	}

	mux := http.NewServeMux()
	
	// Register the split API routes
	api.RegisterRoutes(mux, db, isCloudSaaS)

	// Since we are migrating from DefaultServeMux to a local mux, start the server
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
