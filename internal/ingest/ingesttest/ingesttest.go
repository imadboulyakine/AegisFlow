// Package ingesttest provides test helpers for the ingestion slice: throwaway PostgreSQL
// databases and GitHub Actions OIDC tokens signed by a local JWKS server. It is imported by tests
// only.
package ingesttest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imadboulyakine/aegisflow/internal/intel"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

// EnvTestDatabaseURL names a PostgreSQL 18 server whose user may CREATE DATABASE. Tests that need
// a database are skipped when it is unset.
const EnvTestDatabaseURL = "AEGISFLOW_TEST_DATABASE_URL"

var createMu sync.Mutex

// RandomHex returns n random bytes, hex-encoded.
func RandomHex(tb testing.TB, n int) string {
	tb.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		tb.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// DatabaseURL creates a fresh, empty database on the test server, drops it when the test ends,
// and returns its URL. The test is skipped when EnvTestDatabaseURL is unset.
func DatabaseURL(tb testing.TB) string {
	tb.Helper()
	base := os.Getenv(EnvTestDatabaseURL)
	if base == "" {
		tb.Skipf("%s is not set: skipping PostgreSQL integration test", EnvTestDatabaseURL)
	}
	u, err := url.Parse(base)
	if err != nil {
		tb.Fatalf("%s must be a postgres:// URL", EnvTestDatabaseURL)
	}
	name := "aegisflow_test_" + RandomHex(tb, 6)
	ident := pgx.Identifier{name}.Sanitize()
	admin := func(sql string) {
		tb.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, base)
		if err != nil {
			tb.Fatalf("connect to test server: %v", err)
		}
		defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
		if _, err := conn.Exec(ctx, sql); err != nil {
			tb.Fatalf("%s: %v", sql, err)
		}
	}
	createMu.Lock()
	admin("CREATE DATABASE " + ident)
	createMu.Unlock()
	tb.Cleanup(func() { admin("DROP DATABASE IF EXISTS " + ident + " WITH (FORCE)") })
	u.Path = "/" + name
	return u.String()
}

// Store returns a migrated store on a fresh database (or skips the test).
func Store(tb testing.TB) *store.Store {
	tb.Helper()
	dbURL := DatabaseURL(tb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dbURL, store.Options{MaxConns: 8})
	if err != nil {
		tb.Fatalf("store.Open() = %v", err)
	}
	tb.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		tb.Fatalf("Migrate() = %v", err)
	}
	return s
}

// Issuer is a local GitHub-Actions-like OIDC issuer: an httptest server publishing a JWKS at
// <URL>/.well-known/jwks and a key to mint RS256 tokens with.
type Issuer struct {
	URL    string
	key    *rsa.PrivateKey
	kid    string
	server *httptest.Server
}

// NewIssuer starts an issuer that is closed when the test ends.
func NewIssuer(tb testing.TB) *Issuer {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	iss := &Issuer{key: key, kid: "test-" + RandomHex(tb, 4)}
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": iss.kid,
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		tb.Fatal(err)
	}
	iss.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	tb.Cleanup(iss.server.Close)
	iss.URL = iss.server.URL
	return iss
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Claims returns a complete, valid GitHub Actions claim set for audience, repository IDs and
// commit; tests edit it before calling Mint.
func (i *Issuer) Claims(audience string, repoID, ownerID int64, sha string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": i.URL, "aud": audience, "sub": "repo:octo/demo:ref:refs/heads/main",
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"jti": rand.Text(), "repository": "octo/demo", "repository_id": itoa(repoID),
		"repository_owner": "octo", "repository_owner_id": itoa(ownerID), "repository_visibility": "private",
		"ref": "refs/heads/main", "ref_type": "branch", "sha": sha, "run_id": "4242", "run_number": "7",
		"run_attempt": "1", "workflow": "ci", "workflow_ref": "octo/demo/.github/workflows/ci.yml@refs/heads/main",
		"job_workflow_ref": "octo/demo/.github/workflows/ci.yml@refs/heads/main", "event_name": "push",
		"actor": "octocat", "actor_id": "583231", "runner_environment": "github-hosted",
	}
}

func itoa(n int64) string { return big.NewInt(n).String() }

// Mint signs claims as an RS256 JWT with the issuer's key.
func (i *Issuer) Mint(tb testing.TB, claims map[string]any) string {
	tb.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": i.kid})
	if err != nil {
		tb.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	signing := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		tb.Fatal(err)
	}
	return signing + "." + b64(sig)
}

// Intel returns an intelligence store holding a synthetic KEV catalogue (kev, dated 2026-03-02)
// and synthetic EPSS scores (epss: CVE → probability, percentile 0.9). Test data only: these are
// not real feed values.
func Intel(tb testing.TB, kev []string, epss map[string]float64) *intel.MemoryStore {
	tb.Helper()
	snap := intel.NewSnapshot()
	if len(kev) > 0 {
		entries := make([]map[string]string, 0, len(kev))
		for _, id := range kev {
			entries = append(entries, map[string]string{
				"cveID": id, "vendorProject": "fixture", "product": "fixture", "vulnerabilityName": "synthetic test entry",
				"dateAdded": "2026-03-02", "dueDate": "2026-03-23", "knownRansomwareCampaignUse": "Unknown",
			})
		}
		raw, err := json.Marshal(map[string]any{
			"title": "synthetic KEV (tests)", "catalogVersion": "2026.10.26-test",
			"dateReleased": "2026-10-26T00:00:00Z", "count": len(entries), "vulnerabilities": entries,
		})
		if err != nil {
			tb.Fatal(err)
		}
		cat, err := intel.ParseKEV(bytes.NewReader(raw))
		if err != nil {
			tb.Fatal(err)
		}
		if snap, err = snap.WithKEV(cat, "test", time.Now()); err != nil {
			tb.Fatal(err)
		}
	}
	if len(epss) > 0 {
		var csv strings.Builder
		csv.WriteString("#model_version:v2025.03.14,score_date:2026-10-25T00:00:00+0000\ncve,epss,percentile\n")
		for _, id := range slices.Sorted(maps.Keys(epss)) {
			fmt.Fprintf(&csv, "%s,%.5f,0.90000\n", id, epss[id])
		}
		ds, err := intel.ParseEPSSCSV(strings.NewReader(csv.String()))
		if err != nil {
			tb.Fatal(err)
		}
		if snap, err = snap.WithEPSS(ds, "test", time.Now()); err != nil {
			tb.Fatal(err)
		}
	}
	return intel.NewMemoryStore(snap)
}
