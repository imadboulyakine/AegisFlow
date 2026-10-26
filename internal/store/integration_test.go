package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// Integration tests: they run against PostgreSQL 18 when AEGISFLOW_TEST_DATABASE_URL is set and
// skip otherwise. Each test creates its own database, so they run in parallel.

func embeddedFS(t *testing.T) fstest.MapFS {
	t.Helper()
	sub, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	out := fstest.MapFS{}
	err = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(sub, p)
		out[p] = &fstest.MapFile{Data: b}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMigrateIntegration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestDB(t)

	res, err := s.Migrate(ctx)
	if err != nil {
		t.Fatalf("first Migrate() = %v", err)
	}
	if !slices.Equal(res.Applied, []int{1, 2}) || res.Version != 2 {
		t.Fatalf("first Migrate() = %+v, want applied [1 2] at version 2", res)
	}
	res, err = s.Migrate(ctx)
	if err != nil || len(res.Applied) != 0 || res.Version != 2 {
		t.Fatalf("second Migrate() = %+v, %v; want a no-op at version 2", res, err)
	}

	// A failing migration rolls back completely and records nothing.
	broken := embeddedFS(t)
	broken["0003_broken.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE should_not_exist (id int); SELECT 1/0;")}
	if _, err := migrate(ctx, s.pool, broken, s.log); err == nil || !strings.Contains(err.Error(), "0003_broken") {
		t.Fatalf("broken migration error = %v", err)
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT to_regclass('should_not_exist') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatalf("failed migration left a table behind (exists=%v, err=%v)", exists, err)
	}
	if n := count(t, s, "schema_migrations"); n != 2 {
		t.Fatalf("schema_migrations has %d rows after a failed migration, want 2", n)
	}

	// A new migration applies on top.
	next := embeddedFS(t)
	next["0003_extra.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE extra (id int);")}
	res, err = migrate(ctx, s.pool, next, s.log)
	if err != nil || !slices.Equal(res.Applied, []int{3}) {
		t.Fatalf("Migrate(0003) = %+v, %v", res, err)
	}

	// The binary's embedded set (2 migrations) must refuse a database at version 3.
	if _, err := s.Migrate(ctx); !errors.Is(err, ErrUnknownMigration) {
		t.Fatalf("Migrate() on a newer schema = %v, want ErrUnknownMigration", err)
	}

	// Editing an applied migration file is detected before anything runs.
	edited := embeddedFS(t)
	edited["0001_core.sql"] = &fstest.MapFile{Data: append(edited["0001_core.sql"].Data, []byte("\n-- sneaky edit\n")...)}
	edited["0003_extra.sql"] = next["0003_extra.sql"]
	if _, err := migrate(ctx, s.pool, edited, s.log); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("edited migration = %v, want ErrChecksumMismatch", err)
	}

	// So is tampering with the recorded checksum.
	if _, err := s.pool.Exec(ctx, "UPDATE schema_migrations SET checksum = repeat('0', 64) WHERE version = 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := migrate(ctx, s.pool, next, s.log); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("tampered checksum = %v, want ErrChecksumMismatch", err)
	}
}

func TestMigrateConcurrently(t *testing.T) {
	t.Parallel()
	s := openTestDB(t)
	const n = 8
	var wg sync.WaitGroup
	results := make([]MigrateResult, n)
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() { results[i], errs[i] = s.Migrate(context.Background()) })
	}
	wg.Wait()
	appliedBy := 0
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("Migrate() #%d = %v", i, errs[i])
		}
		if results[i].Version != 2 {
			t.Errorf("Migrate() #%d version = %d", i, results[i].Version)
		}
		if len(results[i].Applied) > 0 {
			appliedBy++
		}
	}
	if appliedBy != 1 {
		t.Errorf("%d migrators applied migrations, want exactly 1", appliedBy)
	}
	if got := count(t, s, "schema_migrations"); got != 2 {
		t.Errorf("schema_migrations rows = %d, want 2", got)
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	if _, err := s.AppendEvidence(ctx, evidenceInput(func(e *EvidenceInput) { e.RunID, e.ArtifactID = f.runID, f.artifactID })); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendAudit(ctx, AuditEntry{Actor: "test", Action: "evidence.ingest", ProjectID: f.projectID}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE evidence SET tool_name = 'forged'",
		"UPDATE evidence SET tool_name = 'forged' WHERE false", // statement-level: even zero rows
		"DELETE FROM evidence",
		"TRUNCATE evidence",
		"UPDATE audit_log SET actor = 'someone-else'",
		"DELETE FROM audit_log WHERE id > 0",
		"TRUNCATE audit_log",
	} {
		_, err := s.pool.Exec(ctx, stmt)
		if err = classify(err); !errors.Is(err, ErrImmutable) || sqlState(err) != immutableSQLState {
			t.Errorf("%s: error = %v, want ErrImmutable (SQLSTATE AF001)", stmt, err)
		}
	}
	if count(t, s, "evidence") != 1 || count(t, s, "audit_log") != 1 {
		t.Error("append-only rows changed")
	}
}

func TestProjectsRunsArtifacts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)

	p := Project{RepoID: 42, OwnerID: 7, RepoFullName: "octo/app"}
	id1, err := s.UpsertProject(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if id2, err := s.UpsertProject(ctx, p); err != nil || id2 != id1 {
		t.Fatalf("idempotent UpsertProject = %d, %v; want %d", id2, err, id1)
	}
	p.RepoFullName = "octo/renamed"
	if id3, err := s.UpsertProject(ctx, p); err != nil || id3 != id1 {
		t.Fatalf("rename UpsertProject = %d, %v", id3, err)
	}
	var name string
	if err := s.pool.QueryRow(ctx, "SELECT repo_full_name FROM projects WHERE id = $1", id1).Scan(&name); err != nil || name != "octo/renamed" {
		t.Fatalf("name = %q, %v", name, err)
	}

	r := validRun()
	r.ProjectID = id1
	r.OIDCClaims = json.RawMessage(`{"repository_id":"42"}`)
	runID, err := s.RecordRun(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Status, r.FinishedAt = RunSuccess, time.Now()
	if again, err := s.RecordRun(ctx, r); err != nil || again != runID {
		t.Fatalf("status update RecordRun = %d, %v", again, err)
	}
	r.Status = RunInProgress // a late "in progress" must not overwrite success
	if _, err := s.RecordRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := s.pool.QueryRow(ctx, "SELECT status FROM pipeline_runs WHERE id = $1", runID).Scan(&status); err != nil || status != "success" {
		t.Fatalf("status = %q, %v; want success", status, err)
	}
	r.SHA = strings.Repeat("f", 40)
	if _, err := s.RecordRun(ctx, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("RecordRun with a different sha = %v, want ErrConflict", err)
	}
	missing := validRun()
	missing.ProjectID = 999_999
	if _, err := s.RecordRun(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecordRun for a missing project = %v, want ErrNotFound", err)
	}

	art := evidence.Artifact{Kind: evidence.ArtifactBinary, Name: "aegisflow", Digest: testDigest}
	a1, err := s.UpsertArtifact(ctx, id1, runID, art)
	if err != nil {
		t.Fatal(err)
	}
	if a2, err := s.UpsertArtifact(ctx, id1, 0, art); err != nil || a2 != a1 {
		t.Fatalf("idempotent UpsertArtifact = %d, %v", a2, err)
	}
	art.Kind = evidence.ArtifactContainerImage
	if _, err := s.UpsertArtifact(ctx, id1, 0, art); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpsertArtifact with another kind = %v, want ErrConflict", err)
	}
	other := seed(t, s, 43)
	if _, err := s.UpsertArtifact(ctx, id1, other.runID, art); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("UpsertArtifact with another project's run = %v, want ErrInvalidInput", err)
	}
	if _, err := s.UpsertArtifact(ctx, id1, 999_999, art); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpsertArtifact with a missing run = %v, want ErrNotFound", err)
	}
	// The same digest in another project is a distinct artifact.
	if a3, err := s.UpsertArtifact(ctx, other.projectID, 0, evidence.Artifact{Kind: evidence.ArtifactBinary, Name: "x", Digest: testDigest}); err != nil || a3 == a1 {
		t.Fatalf("same digest in another project = %d, %v", a3, err)
	}
}

func TestAppendEvidenceIntegration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	other := seed(t, s, 2)

	in := evidenceInput(func(e *EvidenceInput) {
		e.RunID, e.ArtifactID, e.SignerIdentity = f.runID, f.artifactID, "https://github.com/octo/repo/.github/workflows/ci.yml@refs/heads/main"
		e.Body = []byte(`{"bomFormat": "CycloneDX",  "specVersion": "1.6"}`)
	})
	first, err := s.AppendEvidence(ctx, in)
	if err != nil || !first.Created || first.Size != int64(len(in.Body)) || len(first.SHA256) != 64 {
		t.Fatalf("AppendEvidence() = %+v, %v", first, err)
	}
	again, err := s.AppendEvidence(ctx, in)
	if err != nil || again.Created || again.ID != first.ID || again.SHA256 != first.SHA256 {
		t.Fatalf("idempotent AppendEvidence() = %+v, %v; want existing %d", again, err, first.ID)
	}
	var body string
	if err := s.pool.QueryRow(ctx, "SELECT body->>'specVersion' FROM evidence WHERE id = $1", first.ID).Scan(&body); err != nil || body != "1.6" {
		t.Fatalf("stored body = %q, %v", body, err)
	}

	// Unbound evidence (no artifact) is de-duplicated too (UNIQUE NULLS NOT DISTINCT).
	unbound := in
	unbound.ArtifactID = 0
	u1, err := s.AppendEvidence(ctx, unbound)
	if err != nil || !u1.Created {
		t.Fatalf("unbound AppendEvidence() = %+v, %v", u1, err)
	}
	if u2, err := s.AppendEvidence(ctx, unbound); err != nil || u2.Created || u2.ID != u1.ID {
		t.Fatalf("unbound duplicate = %+v, %v", u2, err)
	}

	// Same bytes in another run is new evidence.
	run2 := newRun(t, s, f.projectID, 2000)
	in2 := in
	in2.RunID = run2
	if r2, err := s.AppendEvidence(ctx, in2); err != nil || !r2.Created || r2.ID == first.ID {
		t.Fatalf("other run AppendEvidence() = %+v, %v", r2, err)
	}

	cross := in
	cross.ArtifactID = other.artifactID
	if _, err := s.AppendEvidence(ctx, cross); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-project artifact = %v, want ErrInvalidInput", err)
	}
	missingRun := in
	missingRun.RunID = 999_999
	if _, err := s.AppendEvidence(ctx, missingRun); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing run = %v, want ErrNotFound", err)
	}
	missingArtifact := in
	missingArtifact.ArtifactID = 999_999
	if _, err := s.AppendEvidence(ctx, missingArtifact); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact = %v, want ErrNotFound", err)
	}

	// Defence in depth: the composite foreign keys reject cross-project rows even when the Go
	// checks are bypassed.
	_, err = s.pool.Exec(ctx, `INSERT INTO evidence (project_id, run_id, artifact_id, format, sha256, size, body, tool_name)
VALUES ($1, $2, $3, 'sarif', repeat('a', 64), 2, '{}', 'x')`, f.projectID, f.runID, other.artifactID)
	if !errors.Is(classify(err), ErrNotFound) {
		t.Fatalf("cross-project evidence via SQL = %v, want a foreign key violation", err)
	}
}

// findingByFP returns the stored finding with the given fingerprint (via ListFindings).
func findingByFP(t *testing.T, s *Store, artifactID int64, fp string) FindingRecord {
	t.Helper()
	page, err := s.ListFindings(context.Background(), FindingFilter{ArtifactID: artifactID, Limit: MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range page.Findings {
		if r.Finding.Fingerprint == fp {
			return r
		}
	}
	t.Fatalf("finding %q not found", fp)
	return FindingRecord{}
}

func toolNames(r FindingRecord) []string {
	out := make([]string, len(r.Finding.Tools))
	for i, t := range r.Finding.Tools {
		out[i] = t.Name
	}
	return out
}

func doc(tool string, findings ...evidence.Finding) evidence.Document {
	return evidence.Document{Format: evidence.FormatGrype, Tool: evidence.Tool{Name: tool, Version: "1"}, Findings: findings}
}

func TestIngestLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)

	f1 := vulnFinding("fp-1", "CVE-2024-0001", "pkg:golang/example.com/a@v1.0.0", "grype")
	f1.Vulnerability.Aliases = []string{"GHSA-1111-2222-3333"}
	f1.Vulnerability.CVSS = []evidence.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8}}
	f2 := vulnFinding("fp-2", "CVE-2024-0002", "pkg:golang/example.com/b@v2.0.0", "grype")
	sbom := evidence.Document{
		Format: evidence.FormatCycloneDX, Tool: evidence.Tool{Name: "syft"},
		Components: []evidence.Component{
			{PURL: "pkg:golang/example.com/a@v1.0.0", Name: "example.com/a", Version: "v1.0.0", Direct: true, Licenses: []string{"MIT"}},
			{PURL: "pkg:golang/example.com/c@v3.0.0", Name: "example.com/c", Version: "v3.0.0"},
		},
	}

	res, err := s.IngestDocument(ctx, f.runID, f.artifactID, sbom)
	if err != nil || res.Components != 2 || res.FindingsNew != 0 || res.ProjectID != f.projectID {
		t.Fatalf("SBOM ingest = %+v, %v", res, err)
	}

	scan := doc("grype", f1, f2)
	res, err = s.IngestDocument(ctx, f.runID, f.artifactID, scan)
	if err != nil || res.FindingsNew != 2 || res.FindingsSeen != 0 || res.Vulnerabilities != 2 || len(res.FindingIDs) != 2 {
		t.Fatalf("first scan ingest = %+v, %v", res, err)
	}
	snapshot := func() string {
		page, err := s.ListFindings(ctx, FindingFilter{ArtifactID: f.artifactID})
		if err != nil {
			t.Fatal(err)
		}
		for i := range page.Findings {
			page.Findings[i].UpdatedAt = time.Time{}
		}
		b, _ := json.Marshal(page)
		return string(b) + fmt.Sprint(count(t, s, "components"), count(t, s, "artifact_components"), count(t, s, "vulnerabilities"))
	}
	before := snapshot()

	// Idempotent: the same document again changes nothing.
	res, err = s.IngestDocument(ctx, f.runID, f.artifactID, scan)
	if err != nil || res.FindingsNew != 0 || res.FindingsSeen != 2 || res.FindingsFixed != 0 || res.FindingsReopened != 0 {
		t.Fatalf("repeated ingest = %+v, %v", res, err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("repeated ingest changed state:\nbefore %s\nafter  %s", before, after)
	}
	a := findingByFP(t, s, f.artifactID, "fp-1")
	if a.Finding.Component == nil || !a.Finding.Component.Direct || !slices.Equal(a.Finding.Component.Licenses, []string{"MIT"}) ||
		a.Finding.Vulnerability == nil || len(a.Finding.Vulnerability.CVSS) != 1 || a.Finding.Vulnerability.CVSS[0].BaseScore != 9.8 ||
		!slices.Equal(a.Finding.Vulnerability.Aliases, []string{"GHSA-1111-2222-3333"}) || a.Status != StatusOpen || a.Risk != nil ||
		a.FirstSeenRun != f.runID || a.LastSeenRun != f.runID {
		t.Fatalf("stored finding = %+v (component %+v, vuln %+v)", a, a.Finding.Component, a.Finding.Vulnerability)
	}

	// A second tool reporting fp-1 merges into the same finding.
	g1 := f1
	g1.Tools = []evidence.Tool{{Name: "govulncheck"}}
	g1.Reachability = evidence.ReachabilityCalled
	g1.Severity = evidence.SeverityCritical
	res, err = s.IngestDocument(ctx, f.runID, f.artifactID, doc("govulncheck", g1))
	if err != nil || res.FindingsNew != 0 || res.FindingsSeen != 1 || res.FindingsFixed != 0 {
		t.Fatalf("govulncheck ingest = %+v, %v", res, err)
	}
	a = findingByFP(t, s, f.artifactID, "fp-1")
	if !slices.Equal(toolNames(a), []string{"govulncheck", "grype"}) || a.Finding.Reachability != evidence.ReachabilityCalled ||
		a.Finding.Severity != evidence.SeverityCritical {
		t.Fatalf("merged finding = %+v", a.Finding)
	}
	if b := findingByFP(t, s, f.artifactID, "fp-2"); b.Status != StatusOpen || !slices.Equal(toolNames(b), []string{"grype"}) {
		t.Fatalf("another tool's ingest must not touch fp-2: %+v", b)
	}

	// Run 2: grype no longer reports fp-2 → fixed; fp-1 stays open.
	run2 := newRun(t, s, f.projectID, 2000)
	res, err = s.IngestDocument(ctx, run2, f.artifactID, doc("grype", f1))
	if err != nil || res.FindingsFixed != 1 || len(res.ChangedFindingIDs) != 1 {
		t.Fatalf("run 2 ingest = %+v, %v", res, err)
	}
	if b := findingByFP(t, s, f.artifactID, "fp-2"); b.Status != StatusFixed || b.LastSeenRun != f.runID {
		t.Fatalf("fp-2 = %+v, want fixed with last_seen_run %d", b, f.runID)
	}
	if a = findingByFP(t, s, f.artifactID, "fp-1"); a.LastSeenRun != run2 || a.FirstSeenRun != f.runID {
		t.Fatalf("fp-1 runs = first %d last %d", a.FirstSeenRun, a.LastSeenRun)
	}

	// Run 3: govulncheck stops reporting fp-1, but grype still does → open, tools {grype}.
	run3 := newRun(t, s, f.projectID, 3000)
	res, err = s.IngestDocument(ctx, run3, f.artifactID, doc("govulncheck"))
	if err != nil || res.FindingsFixed != 0 {
		t.Fatalf("run 3 ingest = %+v, %v", res, err)
	}
	if a = findingByFP(t, s, f.artifactID, "fp-1"); a.Status != StatusOpen || !slices.Equal(toolNames(a), []string{"grype"}) {
		t.Fatalf("fp-1 after govulncheck dropped it = %+v", a)
	}

	// Run 4: grype reports fp-2 again (reopened) and no longer fp-1 (fixed).
	run4 := newRun(t, s, f.projectID, 4000)
	res, err = s.IngestDocument(ctx, run4, f.artifactID, doc("grype", f2))
	if err != nil || res.FindingsReopened != 1 || res.FindingsFixed != 1 || res.FindingsNew != 0 {
		t.Fatalf("run 4 ingest = %+v, %v", res, err)
	}
	if b := findingByFP(t, s, f.artifactID, "fp-2"); b.Status != StatusOpen || b.LastSeenRun != run4 {
		t.Fatalf("fp-2 = %+v, want reopened", b)
	}
	if a = findingByFP(t, s, f.artifactID, "fp-1"); a.Status != StatusFixed || !slices.Equal(toolNames(a), []string{"grype"}) {
		t.Fatalf("fp-1 = %+v, want fixed keeping its last tool", a)
	}

	// Accepted findings keep their status when they disappear.
	if _, err := s.pool.Exec(ctx, "UPDATE findings SET status = 'accepted' WHERE fingerprint = 'fp-2'"); err != nil {
		t.Fatal(err)
	}
	run5 := newRun(t, s, f.projectID, 5000)
	if res, err = s.IngestDocument(ctx, run5, f.artifactID, doc("grype")); err != nil || res.FindingsFixed != 0 {
		t.Fatalf("run 5 ingest = %+v, %v", res, err)
	}
	if b := findingByFP(t, s, f.artifactID, "fp-2"); b.Status != StatusAccepted {
		t.Fatalf("accepted finding = %+v", b)
	}

	// Errors: unknown run / artifact, cross-project artifact.
	other := seed(t, s, 2)
	if _, err := s.IngestDocument(ctx, 999_999, f.artifactID, scan); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing run = %v", err)
	}
	if _, err := s.IngestDocument(ctx, f.runID, 999_999, scan); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact = %v", err)
	}
	if _, err := s.IngestDocument(ctx, f.runID, other.artifactID, scan); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-project artifact = %v", err)
	}
}

func TestIngestCodeFindings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	code := evidence.Finding{
		Kind: evidence.FindingCode, Fingerprint: "sarif-1", Title: "SQL injection", Message: "tainted input",
		Severity: evidence.SeverityHigh, RuleID: "G201", Location: &evidence.Location{Path: "internal/db.go", StartLine: 12, EndLine: 14},
	}
	secret := evidence.Finding{Kind: evidence.FindingSecret, Fingerprint: "gl-1", Title: "AWS key", Severity: evidence.SeverityCritical}
	d := evidence.Document{Format: evidence.FormatSARIF, Tool: evidence.Tool{Name: "gosec"}, Findings: []evidence.Finding{code, secret}}
	if res, err := s.IngestDocument(ctx, f.runID, f.artifactID, d); err != nil || res.FindingsNew != 2 {
		t.Fatalf("ingest = %+v, %v", res, err)
	}
	got := findingByFP(t, s, f.artifactID, "sarif-1")
	if got.Finding.Location == nil || *got.Finding.Location != *code.Location || got.Finding.RuleID != "G201" ||
		got.Finding.Vulnerability != nil || got.Finding.Component != nil || got.Finding.Kind != evidence.FindingCode {
		t.Fatalf("code finding = %+v", got.Finding)
	}
	page, err := s.ListFindings(ctx, FindingFilter{Kind: evidence.FindingSecret})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].Finding.Fingerprint != "gl-1" {
		t.Fatalf("kind filter = %+v, %v", page, err)
	}
}

func TestIngestVEX(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	other := seed(t, s, 2)

	const purl = "pkg:golang/example.com/a@v1.0.0"
	f1 := vulnFinding("fp-1", "CVE-2024-0001", purl, "grype")
	f1.Vulnerability.Aliases = []string{"GHSA-1111-2222-3333"}
	f2 := vulnFinding("fp-2", "CVE-2024-0002", "pkg:golang/example.com/b@v2.0.0", "grype")
	if _, err := s.IngestDocument(ctx, f.runID, f.artifactID, doc("grype", f1, f2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestDocument(ctx, other.runID, other.artifactID, doc("grype", f1)); err != nil {
		t.Fatal(err)
	}

	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	vex := func(st evidence.VEXStatement) evidence.Document {
		return evidence.Document{Format: evidence.FormatOpenVEX, Tool: evidence.Tool{Name: "vexctl"}, VEX: []evidence.VEXStatement{st}}
	}
	// not_affected by component PURL, addressed via the GHSA alias, artifact-less document.
	notAffected := vex(evidence.VEXStatement{
		VulnID: "GHSA-1111-2222-3333", Products: []string{purl}, Status: evidence.VEXNotAffected,
		Justification: "vulnerable_code_not_in_execute_path", Author: "security@example.com", Timestamp: t0,
	})
	res, err := s.IngestDocument(ctx, f.runID, 0, notAffected)
	if err != nil || res.VEXStatements != 1 || res.VEXStatusChanges != 1 || len(res.ChangedFindingIDs) != 1 {
		t.Fatalf("VEX ingest = %+v, %v", res, err)
	}
	if got := findingByFP(t, s, f.artifactID, "fp-1"); got.Status != StatusVEXNotAffected {
		t.Fatalf("fp-1 = %s, want vex_not_affected", got.Status)
	}
	if got := findingByFP(t, s, other.artifactID, "fp-1"); got.Status != StatusOpen {
		t.Fatalf("another project's finding = %s, want open (VEX is project-scoped)", got.Status)
	}
	// Re-ingesting the VEX document is a no-op.
	if res, err = s.IngestDocument(ctx, f.runID, 0, notAffected); err != nil || res.VEXStatements != 0 || res.VEXStatusChanges != 0 {
		t.Fatalf("repeated VEX ingest = %+v, %v", res, err)
	}
	// A re-scan keeps the suppression (the finding is still reported).
	if res, err = s.IngestDocument(ctx, f.runID, f.artifactID, doc("grype", f1, f2)); err != nil || res.VEXStatusChanges != 0 {
		t.Fatalf("re-scan = %+v, %v", res, err)
	}
	if got := findingByFP(t, s, f.artifactID, "fp-1"); got.Status != StatusVEXNotAffected {
		t.Fatalf("fp-1 after re-scan = %s", got.Status)
	}
	// A later "affected" statement wins and reopens it.
	affected := vex(evidence.VEXStatement{VulnID: "CVE-2024-0001", Products: []string{purl}, Status: evidence.VEXAffected, Timestamp: t0.Add(time.Hour)})
	if res, err = s.IngestDocument(ctx, f.runID, 0, affected); err != nil || res.VEXStatusChanges != 1 {
		t.Fatalf("affected VEX = %+v, %v", res, err)
	}
	if got := findingByFP(t, s, f.artifactID, "fp-1"); got.Status != StatusOpen {
		t.Fatalf("fp-1 after affected = %s, want open", got.Status)
	}
	// An older statement does not override the newer one.
	older := vex(evidence.VEXStatement{VulnID: "CVE-2024-0001", Products: []string{purl}, Status: evidence.VEXNotAffected,
		Justification: "component_not_present", Timestamp: t0.Add(-time.Hour)})
	if res, err = s.IngestDocument(ctx, f.runID, 0, older); err != nil || res.VEXStatements != 1 || res.VEXStatusChanges != 0 {
		t.Fatalf("older VEX = %+v, %v", res, err)
	}
	// Product = artifact digest, embedded in a scan document for the same artifact.
	withVEX := doc("grype", f2)
	withVEX.VEX = []evidence.VEXStatement{{VulnID: "CVE-2024-0002", Products: []string{f.digest}, Status: evidence.VEXNotAffected,
		Justification: "inline_mitigations_already_exist", Timestamp: t0}}
	if res, err = s.IngestDocument(ctx, f.runID, f.artifactID, withVEX); err != nil || res.VEXStatusChanges != 1 {
		t.Fatalf("digest VEX = %+v, %v", res, err)
	}
	if got := findingByFP(t, s, f.artifactID, "fp-2"); got.Status != StatusVEXNotAffected {
		t.Fatalf("fp-2 = %s, want vex_not_affected", got.Status)
	}
	if n := count(t, s, "vex_statements"); n != 4 {
		t.Fatalf("vex_statements = %d, want 4", n)
	}
}

func TestListFindingsPagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	other := seed(t, s, 2)

	const total = 23
	findings := make([]evidence.Finding, total)
	for i := range total {
		findings[i] = vulnFinding(fmt.Sprintf("fp-%02d", i), fmt.Sprintf("CVE-2024-%04d", 1000+i), fmt.Sprintf("pkg:npm/p%d@1.0.0", i), "grype")
	}
	res, err := s.IngestDocument(ctx, f.runID, f.artifactID, doc("grype", findings...))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestDocument(ctx, other.runID, other.artifactID, doc("grype", findings[0])); err != nil {
		t.Fatal(err)
	}
	// Score 15 of them (some ties), leave 8 unscored.
	updates := make([]RiskUpdate, 0, 15)
	for i, id := range res.FindingIDs[:15] {
		score := float64((i * 7) % 100)
		if i%5 == 0 {
			score = 80 // ties broken by ID
		}
		tier := TierP3
		switch {
		case score >= 70:
			tier = TierP1
		case score >= 40:
			tier = TierP2
		}
		updates = append(updates, RiskUpdate{FindingID: id, Risk: Risk{Score: score, Tier: tier, Explanation: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i))}})
	}
	if err := s.UpdateFindingRisks(ctx, updates); err != nil {
		t.Fatal(err)
	}

	var all []FindingRecord
	cursor := ""
	pages := 0
	for {
		page, err := s.ListFindings(ctx, FindingFilter{ArtifactID: f.artifactID, Limit: 4, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		all = append(all, page.Findings...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 20 {
			t.Fatal("pagination does not terminate")
		}
	}
	if len(all) != total || pages != 6 {
		t.Fatalf("got %d findings in %d pages, want %d in 6", len(all), pages, total)
	}
	seen := map[int64]bool{}
	key := func(r FindingRecord) float64 {
		if r.Risk == nil {
			return -1
		}
		return r.Risk.Score
	}
	for i, r := range all {
		if seen[r.ID] {
			t.Fatalf("finding %d returned twice", r.ID)
		}
		seen[r.ID] = true
		if i > 0 {
			prev := all[i-1]
			if key(prev) < key(r) || (key(prev) == key(r) && prev.ID < r.ID) {
				t.Fatalf("order broken at %d: (%v,%d) before (%v,%d)", i, key(prev), prev.ID, key(r), r.ID)
			}
		}
		if r.Risk != nil && (len(r.Risk.Explanation) == 0 || r.Risk.ScoredAt.IsZero()) {
			t.Fatalf("risk not round-tripped: %+v", r.Risk)
		}
	}

	countWith := func(filter FindingFilter) int {
		filter.Limit = MaxPageSize
		page, err := s.ListFindings(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		return len(page.Findings)
	}
	p1 := 0
	for _, u := range updates {
		if u.Risk.Tier == TierP1 {
			p1++
		}
	}
	if got := countWith(FindingFilter{ArtifactID: f.artifactID, Tier: TierP1}); got != p1 {
		t.Errorf("tier filter = %d, want %d", got, p1)
	}
	if got := countWith(FindingFilter{ProjectID: other.projectID}); got != 1 {
		t.Errorf("project filter = %d, want 1", got)
	}
	if got := countWith(FindingFilter{}); got != total+1 {
		t.Errorf("no filter = %d, want %d", got, total+1)
	}
	if got := countWith(FindingFilter{Status: StatusFixed}); got != 0 {
		t.Errorf("status filter = %d, want 0", got)
	}
	if got := countWith(FindingFilter{Kind: evidence.FindingVulnerability, Status: StatusOpen}); got != total+1 {
		t.Errorf("kind+status filter = %d, want %d", got, total+1)
	}
	if page, err := s.ListFindings(ctx, FindingFilter{ArtifactID: f.artifactID}); err != nil || len(page.Findings) != total || page.NextCursor != "" {
		t.Errorf("default page = %d findings, cursor %q, %v", len(page.Findings), page.NextCursor, err)
	}
}

func TestUpdateFindingRiskIntegration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	res, err := s.IngestDocument(ctx, f.runID, f.artifactID, doc("grype", vulnFinding("fp", "CVE-2024-0001", "pkg:npm/a@1", "grype")))
	if err != nil {
		t.Fatal(err)
	}
	id := res.FindingIDs[0]
	risk := Risk{Score: 72.5, Tier: TierP1, Explanation: json.RawMessage(`{"S":0.98,"E":0.4,"K":0,"R":1,"X":1,"V":1}`)}
	if err := s.UpdateFindingRisk(ctx, id, risk); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateFindingRisk(ctx, 999_999, risk); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing finding = %v, want ErrNotFound", err)
	}
	// All-or-nothing: a batch with one missing finding changes nothing.
	lower := risk
	lower.Score, lower.Tier = 10, TierP3
	err = s.UpdateFindingRisks(ctx, []RiskUpdate{{FindingID: id, Risk: lower}, {FindingID: 999_999, Risk: lower}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("partial batch = %v, want ErrNotFound", err)
	}
	got := findingByFP(t, s, f.artifactID, "fp")
	if got.Risk == nil || got.Risk.Score != 72.5 || got.Risk.Tier != TierP1 {
		t.Fatalf("risk = %+v, want the first update kept", got.Risk)
	}
	var expl map[string]float64
	if err := json.Unmarshal(got.Risk.Explanation, &expl); err != nil || expl["S"] != 0.98 {
		t.Fatalf("explanation = %s, %v", got.Risk.Explanation, err)
	}
}

func TestConcurrentIngests(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	g := seed(t, s, 2)

	// Shared packages across projects, listed in different orders, to exercise lock ordering.
	var fs1, fs2 []evidence.Finding
	for i := range 40 {
		purl := fmt.Sprintf("pkg:npm/shared-%02d@1.0.0", i)
		vid := fmt.Sprintf("CVE-2025-%04d", 2000+i)
		fs1 = append(fs1, vulnFinding("a-"+purl, vid, purl, "grype"))
		fs2 = append([]evidence.Finding{vulnFinding("b-"+purl, vid, purl, "grype")}, fs2...)
	}
	d1, d2 := doc("grype", fs1...), doc("grype", fs2...)

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, 2*workers)
	news := make(chan int, 2*workers)
	for i := range workers {
		wg.Go(func() {
			r, err := s.IngestDocument(ctx, f.runID, f.artifactID, d1)
			errs <- err
			news <- r.FindingsNew
		})
		wg.Go(func() {
			target, d := g, d2
			if i%2 == 0 {
				target, d = f, d1
			}
			r, err := s.IngestDocument(ctx, target.runID, target.artifactID, d)
			errs <- err
			news <- r.FindingsNew
		})
	}
	wg.Wait()
	close(errs)
	close(news)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent IngestDocument() = %v", err)
		}
	}
	totalNew := 0
	for n := range news {
		totalNew += n
	}
	if totalNew != 80 {
		t.Errorf("findings created across workers = %d, want 80 (each created exactly once)", totalNew)
	}
	if n := count(t, s, "findings"); n != 80 {
		t.Errorf("findings rows = %d, want 80", n)
	}
	if n := count(t, s, "components"); n != 40 {
		t.Errorf("components rows = %d, want 40", n)
	}
	if n := count(t, s, "vulnerabilities"); n != 40 {
		t.Errorf("vulnerabilities rows = %d, want 40", n)
	}
}

func TestAuditAndIntel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)

	id, err := s.AppendAudit(ctx, AuditEntry{
		Actor: "github-repo:1", Action: "evidence.ingest", Target: "artifact:" + f.digest, ProjectID: f.projectID,
		Details: json.RawMessage(`{"evidence_id":1}`),
	})
	if err != nil || id <= 0 {
		t.Fatalf("AppendAudit() = %d, %v", id, err)
	}
	if _, err := s.AppendAudit(ctx, AuditEntry{Actor: "system", Action: "intel.sync"}); err != nil {
		t.Fatalf("global AppendAudit() = %v", err)
	}
	if _, err := s.AppendAudit(ctx, AuditEntry{Actor: "system", Action: "x", ProjectID: 999_999}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AppendAudit() for a missing project = %v, want ErrNotFound", err)
	}

	day1 := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	p := func(v float64) *float64 { return &v }
	b := func(v bool) *bool { return &v }
	// Two snapshots for the same CVE and UTC day in one batch are ambiguous: rejected.
	n, err := s.RecordVulnIntel(ctx, []VulnIntel{
		{CVE: "CVE-2024-0001", Date: day1, EPSS: p(0.1)},
		{CVE: "CVE-2024-0001", Date: day1.Add(5 * time.Hour), KEV: b(true)},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate (CVE, day) in one batch = %d, %v; want ErrInvalidInput", n, err)
	}
	if n, err = s.RecordVulnIntel(ctx, []VulnIntel{{CVE: "CVE-2024-0001", Date: day1, EPSS: p(0.1), EPSSPercentile: p(0.5)}}); err != nil || n != 1 {
		t.Fatalf("EPSS snapshot = %d, %v", n, err)
	}
	// KEV sync on the same day merges into the row; a newer EPSS-only day does not hide KEV.
	if _, err = s.RecordVulnIntel(ctx, []VulnIntel{{CVE: "CVE-2024-0001", Date: day1, KEV: b(true), KEVDateAdded: day1.AddDate(0, -1, 0), KEVRansomware: b(true)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RecordVulnIntel(ctx, []VulnIntel{{CVE: "CVE-2024-0001", Date: day2, EPSS: p(0.3), EPSSPercentile: p(0.9)}, {CVE: "CVE-2024-0002", Date: day2, KEV: b(false)}}); err != nil {
		t.Fatal(err)
	}
	if got := count(t, s, "vuln_intel"); got != 3 {
		t.Fatalf("vuln_intel rows = %d, want 3", got)
	}
	latest, err := s.LatestVulnIntel(ctx, []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-9999"})
	if err != nil {
		t.Fatal(err)
	}
	one := latest["CVE-2024-0001"]
	if one.EPSS == nil || *one.EPSS != 0.3 || !one.EPSSDate.Equal(day2) || one.KEV == nil || !*one.KEV ||
		!one.KEVDate.Equal(day1) || !one.KEVDateAdded.Equal(day1.AddDate(0, -1, 0)) || one.KEVRansomware == nil || !*one.KEVRansomware {
		t.Fatalf("latest CVE-2024-0001 = %+v", one)
	}
	two := latest["CVE-2024-0002"]
	if two.EPSS != nil || two.KEV == nil || *two.KEV || !two.EPSSDate.IsZero() {
		t.Fatalf("latest CVE-2024-0002 = %+v", two)
	}
	if _, ok := latest["CVE-2024-9999"]; ok || len(latest) != 2 {
		t.Fatalf("latest = %v", latest)
	}
}

func TestDatabaseConstraintsBackGoValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := testStore(t)
	f := seed(t, s, 1)
	if _, err := s.IngestDocument(ctx, f.runID, f.artifactID, doc("grype", vulnFinding("fp", "CVE-2024-0001", "pkg:npm/a@1", "grype"))); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"INSERT INTO projects (repo_id, repo_full_name, owner_id) VALUES (-1, 'a/b', 1)",
		"INSERT INTO artifacts (project_id, kind, name, digest) VALUES (1, 'binary', 'x', 'latest')",
		"UPDATE findings SET status = 'ignored'",
		"UPDATE findings SET risk_score = 'NaN', risk_tier = 'P1', risk_explanation = '{}', risk_scored_at = now()",
		"UPDATE findings SET risk_score = 50", // partial risk: tier/explanation missing
		"INSERT INTO vuln_intel (cve_id, snapshot_date, epss) VALUES ('CVE-2024-0001', current_date, 2)",
	} {
		_, err := s.pool.Exec(ctx, stmt)
		if !errors.Is(classify(err), ErrInvalidInput) {
			t.Errorf("%s: error = %v, want a CHECK violation (ErrInvalidInput)", stmt, err)
		}
	}
}

func TestOpenAndPing(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Ping(ctx); err == nil {
		t.Fatal("Ping() with a cancelled context succeeded")
	}
}
