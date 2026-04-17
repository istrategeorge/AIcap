// Package migrate applies schema migrations embedded in the binary against a
// Postgres database. It is intentionally tiny — ~100 lines of lex-sorted,
// one-migration-per-transaction execution backed by a schema_migrations
// tracking table. We do not need the feature surface of golang-migrate
// (down-migrations, drivers for 10 databases, file://… URIs) and every feature
// we add is a foot-gun we have to maintain.
//
// Design choices worth calling out:
//
//   - Migrations ship inside the binary via embed.FS. Ops cannot forget to
//     deploy the SQL; whatever `go build` saw is what runs.
//   - Each file runs in its own transaction. If a migration fails mid-file
//     the DB stays consistent (modulo DDL that Postgres implicitly commits —
//     CREATE INDEX CONCURRENTLY, notably, which we do not use).
//   - We record the filename AFTER the migration succeeds, inside the same
//     transaction. A crash between "BEGIN" and "COMMIT" leaves the DB as if
//     the migration never ran.
//   - Every migration body uses IF NOT EXISTS so replaying against a database
//     that was hand-migrated before the runner existed is a no-op. The first
//     production run just seeds schema_migrations with what's already there.
//   - Filenames are lex-sorted. Keep the zero-padded numeric prefix
//     (00001_, 00002_, …) or the ordering will silently change when a
//     00010_ migration appears.
package migrate

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var embedded embed.FS

// Apply brings the database up to the latest migration embedded in the
// binary. It is safe to call at process startup: already-applied migrations
// are skipped, and concurrent callers race on the advisory lock rather than
// each trying to apply the same SQL.
func Apply(db *sql.DB) error {
	return apply(db, embedded, "migrations")
}

// apply is the testable core. The test suite passes its own fs.FS so we can
// exercise the runner against synthetic migrations without touching the real
// embedded set.
func apply(db *sql.DB, src fs.FS, dir string) error {
	// Advisory lock so two processes racing to boot (common on rolling deploys)
	// don't both try to run the same migration. The key is arbitrary but must
	// be stable across deploys — change it and you break the mutual exclusion.
	if _, err := db.Exec(`SELECT pg_advisory_lock(4217493821)`); err != nil {
		return fmt.Errorf("acquire advisory lock: %w", err)
	}
	defer func() {
		if _, err := db.Exec(`SELECT pg_advisory_unlock(4217493821)`); err != nil {
			log.Printf("migrate: failed to release advisory lock: %v", err)
		}
	}()

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := loadApplied(db)
	if err != nil {
		return err
	}

	files, err := listMigrations(src, dir)
	if err != nil {
		return err
	}

	for _, name := range files {
		if applied[name] {
			continue
		}
		body, err := fs.ReadFile(src, dir+"/"+name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := runOne(db, name, string(body)); err != nil {
			return err
		}
		log.Printf("migrate: applied %s", name)
	}
	return nil
}

// runOne executes a single migration body inside a transaction. The insert
// into schema_migrations is in the same transaction as the DDL so a failure
// between "ran the SQL" and "recorded that it ran" is impossible.
func runOne(db *sql.DB, name, body string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin %s: %w", name, err)
	}
	defer tx.Rollback() // no-op after Commit

	if _, err := tx.Exec(body); err != nil {
		return fmt.Errorf("apply %s: %w", name, err)
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (filename) VALUES ($1)`, name,
	); err != nil {
		return fmt.Errorf("record %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", name, err)
	}
	return nil
}

func loadApplied(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`SELECT filename FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := map[string]bool{}
	for rows.Next() {
		var fn string
		if err := rows.Scan(&fn); err != nil {
			return nil, err
		}
		applied[fn] = true
	}
	return applied, rows.Err()
}

func listMigrations(src fs.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(src, dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}
