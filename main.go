package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aicap/pkg/api"
	"aicap/pkg/compliance"
	"aicap/pkg/httplog"
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

	httplog.Init()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	slog.Info("starting AIcap server", slog.String("port", port))

	var db *sql.DB
	isCloudSaaS := false

	// Connect to Supabase
	dbURL := os.Getenv("SUPABASE_DB_URL")
	if dbURL != "" {
		isCloudSaaS = true
		var err error
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			slog.Error("opening database", slog.Any("error", err))
			os.Exit(1)
		}
		if err = db.Ping(); err != nil {
			slog.Error("connecting to database", slog.Any("error", err))
			os.Exit(1)
		}
		slog.Info("connected to Supabase PostgreSQL")

		// RUN_MIGRATIONS=true tells the server to apply any pending schema
		// migrations before it starts accepting traffic. Opt-in (not default)
		// because some deployment flows prefer a separate `aicap --migrate`
		// step in CI so a bad migration fails the pipeline rather than a
		// running pod. Safe to enable on the staging/Render setup where a
		// single instance boots on each deploy.
		if os.Getenv("RUN_MIGRATIONS") == "true" {
			if err := migrate.Apply(db); err != nil {
				slog.Error("applying migrations", slog.Any("error", err))
				os.Exit(1)
			}
		}
	} else {
		if os.Getenv("RENDER") == "true" || os.Getenv("VERCEL") == "true" {
			slog.Error("SUPABASE_DB_URL not set in cloud environment — database required for SaaS features")
			os.Exit(1)
		}
		slog.Warn("SUPABASE_DB_URL not set; running without a database")
		db = nil
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, db, isCloudSaaS)

	// Wrap the mux in request-ID + logger middleware so every handler call
	// produces structured log lines correlated by request_id.
	handler := httplog.Middleware(mux)

	// Timeouts are set to sane production values. Without them a slow client
	// (or a misbehaving Stripe webhook retry) can hold a goroutine open
	// indefinitely. Write timeout is generous to cover the largest expected
	// response (a full proof-drill ledger page).
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown: catch SIGINT/SIGTERM (Render sends SIGTERM before
	// redeploy), stop accepting new connections, and give in-flight requests
	// up to 25s to finish. We intentionally pick a timeout shorter than
	// Render's 30s kill window so our own log line about which requests we
	// abandoned still makes it out before the process dies.
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		slog.Error("server exited", slog.Any("error", err))
		os.Exit(1)
	case sig := <-stop:
		slog.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed; forcing close", slog.Any("error", err))
		_ = srv.Close()
	} else {
		slog.Info("server shut down cleanly")
	}
	if db != nil {
		_ = db.Close()
	}
}
