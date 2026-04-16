package migrate

import (
	"database/sql"
	"os"
	"testing"
	"testing/fstest"

	_ "github.com/lib/pq"
)

// testDB opens a connection to TEST_DATABASE_URL or skips. We don't try to
// spin up a container here — the integration suite (see pkg/api) does that
// once; this package-level test just verifies the runner's logic end-to-end
// whenever a Postgres is reachable. CI sets TEST_DATABASE_URL; on a dev laptop
// without one, the tests skip rather than fail.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping migrate integration test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return db
}

// cleanSchema drops every object the runner might create. Called at the start
// of each test so they're independent — we don't want a prior test's leftover
// schema_migrations rows to mask a bug.
func cleanSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`DROP TABLE IF EXISTS schema_migrations`,
		`DROP TABLE IF EXISTS widgets`,
		`DROP TABLE IF EXISTS gadgets`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("cleanup %q: %v", s, err)
		}
	}
}

func TestApply_RunsAllMigrations(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	cleanSchema(t, db)

	src := fstest.MapFS{
		"m/00001_widgets.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE widgets (id INT PRIMARY KEY);`),
		},
		"m/00002_gadgets.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE gadgets (id INT PRIMARY KEY);`),
		},
	}
	if err := apply(db, src, "m"); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Both tables must exist.
	for _, tbl := range []string{"widgets", "gadgets"} {
		var reg string
		err := db.QueryRow(`SELECT to_regclass($1)::text`, tbl).Scan(&reg)
		if err != nil || reg != tbl {
			t.Errorf("%s not created (got %q, err=%v)", tbl, reg, err)
		}
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count)
	if count != 2 {
		t.Errorf("schema_migrations row count = %d, want 2", count)
	}
}

// TestApply_SkipsAlreadyApplied proves the runner is idempotent — a second
// call against the same database is a no-op. This is what lets us safely set
// RUN_MIGRATIONS=true on every server boot.
func TestApply_SkipsAlreadyApplied(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	cleanSchema(t, db)

	src := fstest.MapFS{
		"m/00001_widgets.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE widgets (id INT PRIMARY KEY);`),
		},
	}
	if err := apply(db, src, "m"); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// Second call must not re-run the CREATE TABLE (which would error because
	// the table now exists — we intentionally did NOT use IF NOT EXISTS here
	// so the test fails loudly if the skip logic breaks).
	if err := apply(db, src, "m"); err != nil {
		t.Fatalf("second apply: %v", err)
	}
}

// TestApply_FailedMigrationRollsBack ensures a migration that errors leaves
// no trace — no partial schema, no schema_migrations row. Otherwise a fix
// + retry would fail because the runner would think the broken migration
// had already succeeded.
func TestApply_FailedMigrationRollsBack(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	cleanSchema(t, db)

	src := fstest.MapFS{
		"m/00001_good.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE widgets (id INT PRIMARY KEY);`),
		},
		"m/00002_bad.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE gadgets (id NONSENSE PRIMARY KEY);`),
		},
	}
	err := apply(db, src, "m")
	if err == nil {
		t.Fatal("expected apply to fail on 00002_bad.sql")
	}

	// The good migration should have committed; the bad one must not have.
	var recorded []string
	rows, qErr := db.Query(`SELECT filename FROM schema_migrations ORDER BY filename`)
	if qErr != nil {
		t.Fatalf("query: %v", qErr)
	}
	defer rows.Close()
	for rows.Next() {
		var fn string
		rows.Scan(&fn)
		recorded = append(recorded, fn)
	}
	if len(recorded) != 1 || recorded[0] != "00001_good.sql" {
		t.Errorf("recorded = %v, want [00001_good.sql]", recorded)
	}

	// And the failed migration's table must not exist.
	var reg sql.NullString
	db.QueryRow(`SELECT to_regclass('gadgets')::text`).Scan(&reg)
	if reg.Valid {
		t.Errorf("gadgets table was created despite migration failure")
	}
}

// TestApply_LexicographicOrdering catches the classic mistake of naming
// migrations 1_, 2_, …, 10_ — where "10_" sorts before "2_" and runs in
// the wrong order. Our convention is zero-padded 00001_ prefixes; this test
// verifies the runner honours pure lex order so that convention is enforced.
func TestApply_LexicographicOrdering(t *testing.T) {
	files, err := listMigrations(fstest.MapFS{
		"m/00002_b.sql":  &fstest.MapFile{Data: []byte(`SELECT 1`)},
		"m/00001_a.sql":  &fstest.MapFile{Data: []byte(`SELECT 1`)},
		"m/00010_j.sql":  &fstest.MapFile{Data: []byte(`SELECT 1`)},
		"m/00003_c.sql":  &fstest.MapFile{Data: []byte(`SELECT 1`)},
		"m/readme.txt":   &fstest.MapFile{Data: []byte(`ignored`)},
	}, "m")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"00001_a.sql", "00002_b.sql", "00003_c.sql", "00010_j.sql"}
	if len(files) != len(want) {
		t.Fatalf("got %v, want %v", files, want)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, files[i], want[i])
		}
	}
}
