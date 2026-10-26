package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// envTestDatabaseURL points the integration tests at a PostgreSQL 18 server whose user may
// CREATE DATABASE (e.g. the CI service container). Each test gets its own throwaway database.
const envTestDatabaseURL = "AEGISFLOW_TEST_DATABASE_URL"

var createDBMu sync.Mutex // CREATE DATABASE copies template1; keep it sequential

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// openTestDB creates a fresh, empty database and returns an unmigrated Store on it. The test is
// skipped when AEGISFLOW_TEST_DATABASE_URL is unset.
func openTestDB(t *testing.T) *Store {
	t.Helper()
	base := os.Getenv(envTestDatabaseURL)
	if base == "" {
		t.Skipf("%s is not set: skipping PostgreSQL integration test", envTestDatabaseURL)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("%s must be a postgres:// URL", envTestDatabaseURL)
	}
	name := "aegisflow_test_" + randomHex(t, 6)
	ident := pgx.Identifier{name}.Sanitize()
	admin := func(sql string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Fatalf("connect to test server: %v", err)
		}
		defer conn.Close(context.WithoutCancel(ctx))
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	createDBMu.Lock()
	admin("CREATE DATABASE " + ident)
	createDBMu.Unlock()
	t.Cleanup(func() { admin("DROP DATABASE IF EXISTS " + ident + " WITH (FORCE)") })

	u.Path = "/" + name
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // fail fast if the server is gone
	defer cancel()
	s, err := Open(ctx, u.String(), Options{MaxConns: 16})
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// testStore returns a migrated Store on a fresh database (or skips the test).
func testStore(t *testing.T) *Store {
	t.Helper()
	s := openTestDB(t)
	if _, err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate() = %v", err)
	}
	return s
}

// fixture is a project with one run and one artifact.
type fixture struct {
	projectID, runID, artifactID int64
	digest                       string
}

// seed creates a project (repoID), a run and a container-image artifact.
func seed(t *testing.T, s *Store, repoID int64) fixture {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, Project{RepoID: repoID, OwnerID: 7, RepoFullName: "octo/repo" + randomHex(t, 2)})
	if err != nil {
		t.Fatalf("UpsertProject() = %v", err)
	}
	f := fixture{projectID: pid, digest: "sha256:" + randomHex(t, 32)}
	f.runID = newRun(t, s, pid, 1000)
	f.artifactID, err = s.UpsertArtifact(ctx, pid, f.runID, evidence.Artifact{
		Kind: evidence.ArtifactContainerImage, Name: "ghcr.io/octo/app", Digest: f.digest,
	})
	if err != nil {
		t.Fatalf("UpsertArtifact() = %v", err)
	}
	return f
}

func newRun(t *testing.T, s *Store, projectID, runID int64) int64 {
	t.Helper()
	r := validRun()
	r.ProjectID, r.RunID = projectID, runID
	id, err := s.RecordRun(context.Background(), r)
	if err != nil {
		t.Fatalf("RecordRun() = %v", err)
	}
	return id
}

// count returns SELECT count(*) for a fixed table name used by tests.
func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.pool.QueryRow(context.Background(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
