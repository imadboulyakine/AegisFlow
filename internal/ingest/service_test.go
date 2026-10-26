package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/auth/ghoidc"
	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/ingest/ingesttest"
	"github.com/imadboulyakine/aegisflow/internal/risk"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

const (
	testSHA    = "0123456789abcdef0123456789abcdef01234567"
	testDigest = "sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "evidence", "normalize", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testClaims() *ghoidc.Claims {
	return &ghoidc.Claims{
		Issuer: ghoidc.DefaultIssuer, Subject: "repo:octo/demo:ref:refs/heads/main", Audience: []string{"aegisflow"},
		Repository: "octo/demo", RepositoryID: "101", RepositoryOwner: "octo", RepositoryOwnerID: "202",
		Ref: "refs/heads/main", SHA: testSHA, RunID: "4242", RunAttempt: "2", EventName: "push",
		WorkflowRef: "octo/demo/.github/workflows/ci.yml@refs/heads/main", ActorID: "583231",
	}
}

func imageRequest(body []byte) Request {
	return Request{
		Artifact: evidence.Artifact{Kind: evidence.ArtifactContainerImage, Name: "ghcr.io/octo/demo", Digest: testDigest},
		Commit:   testSHA, Evidence: body,
	}
}

// fakeStore is an in-memory Store: findings are kept per fingerprint, IDs are assigned in order.
type fakeStore struct {
	mu       sync.Mutex
	err      map[string]error // method name → error to return
	projects []store.Project
	runs     []store.Run
	evidence []store.EvidenceInput
	findings map[int64]store.FindingRecord
	byFP     map[string]int64
	vex      map[int64]evidence.VEXStatement
	risks    map[int64]store.Risk
	audits   []store.AuditEntry
	statuses map[string]store.FindingStatus // fingerprint → status to assign
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		err: map[string]error{}, findings: map[int64]store.FindingRecord{}, byFP: map[string]int64{},
		vex: map[int64]evidence.VEXStatement{}, risks: map[int64]store.Risk{}, statuses: map[string]store.FindingStatus{},
	}
}

func (f *fakeStore) fail(method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err[method]
}

func (f *fakeStore) UpsertProject(_ context.Context, p store.Project) (int64, error) {
	if err := f.fail("UpsertProject"); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.projects = append(f.projects, p)
	return 1, nil
}

func (f *fakeStore) RecordRun(_ context.Context, r store.Run) (int64, error) {
	if err := f.fail("RecordRun"); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, r)
	return 2, nil
}

func (f *fakeStore) UpsertArtifact(context.Context, int64, int64, evidence.Artifact) (int64, error) {
	if err := f.fail("UpsertArtifact"); err != nil {
		return 0, err
	}
	return 3, nil
}

func (f *fakeStore) AppendEvidence(_ context.Context, in store.EvidenceInput) (store.EvidenceRecord, error) {
	if err := f.fail("AppendEvidence"); err != nil {
		return store.EvidenceRecord{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evidence = append(f.evidence, in)
	return store.EvidenceRecord{ID: int64(len(f.evidence)), SHA256: "ab", Size: int64(len(in.Body)), Created: len(f.evidence) == 1}, nil
}

func (f *fakeStore) IngestDocument(_ context.Context, _, artifactID int64, doc evidence.Document) (store.IngestResult, error) {
	if err := f.fail("IngestDocument"); err != nil {
		return store.IngestResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	res := store.IngestResult{ProjectID: 1, Components: len(doc.Components), VEXStatements: len(doc.VEX)}
	for _, fd := range doc.Findings {
		id, ok := f.byFP[fd.Fingerprint]
		if !ok {
			id = int64(len(f.byFP) + 10)
			f.byFP[fd.Fingerprint] = id
			res.FindingsNew++
		} else {
			res.FindingsSeen++
		}
		status := store.StatusOpen
		if st, ok := f.statuses[fd.Fingerprint]; ok {
			status = st
		}
		f.findings[id] = store.FindingRecord{ID: id, ArtifactID: artifactID, Finding: fd, Status: status}
		res.FindingIDs = append(res.FindingIDs, id)
	}
	slices.Sort(res.FindingIDs)
	return res, nil
}

func (f *fakeStore) GetFindings(_ context.Context, ids []int64) ([]store.FindingRecord, error) {
	if err := f.fail("GetFindings"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.FindingRecord
	for _, id := range ids {
		if r, ok := f.findings[id]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeStore) ApplicableVEX(_ context.Context, ids []int64) (map[int64]evidence.VEXStatement, error) {
	if err := f.fail("ApplicableVEX"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[int64]evidence.VEXStatement{}
	for _, id := range ids {
		if st, ok := f.vex[id]; ok {
			out[id] = st
		}
	}
	return out, nil
}

func (f *fakeStore) UpdateFindingRisks(_ context.Context, updates []store.RiskUpdate) error {
	if err := f.fail("UpdateFindingRisks"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range updates {
		if !json.Valid(u.Risk.Explanation) {
			return fmt.Errorf("%w: explanation", store.ErrInvalidInput)
		}
		f.risks[u.FindingID] = u.Risk
	}
	return nil
}

func (f *fakeStore) AppendAudit(_ context.Context, e store.AuditEntry) (int64, error) {
	if err := f.fail("AppendAudit"); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, e)
	return int64(len(f.audits)), nil
}

func newService(t *testing.T, st Store, opts Options) *Service {
	t.Helper()
	opts.Store = st
	svc, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestNewOptions(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Error("New without store succeeded")
	}
	if _, err := New(Options{Store: newFakeStore(), Exposure: "public"}); err == nil {
		t.Error("New with bad exposure succeeded")
	}
	if _, err := New(Options{Store: newFakeStore(), MaxEvidenceBytes: store.MaxEvidenceSize + 1}); err == nil {
		t.Error("New above the store limit succeeded")
	}
	svc, err := New(Options{Store: newFakeStore()})
	if err != nil || svc.MaxEvidenceBytes() != DefaultMaxEvidenceBytes || svc.exposure != risk.ExposureUnknown {
		t.Fatalf("New defaults = %+v, %v", svc, err)
	}
}

func TestIngestGrype(t *testing.T) {
	t.Parallel()
	st := newFakeStore()
	var logs bytes.Buffer
	svc := newService(t, st, Options{
		Intel:    ingesttest.Intel(t, []string{"CVE-2022-32149"}, map[string]float64{"CVE-2022-32149": 0.6}),
		Exposure: risk.ExposureInternet,
		Logger:   slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	res, err := svc.Ingest(t.Context(), testClaims(), imageRequest(fixture(t, "grype-image-handbuilt.json")))
	if err != nil {
		t.Fatal(err)
	}
	if res.ProjectID != 1 || res.RunID != 2 || res.ArtifactID != 3 || !res.Evidence.Created ||
		res.Evidence.Format != evidence.FormatGrype || res.Evidence.Tool.Name != "grype" || len(res.Warnings) != 0 {
		t.Fatalf("result = %+v", res)
	}
	if res.Counts.FindingsNew != 2 || res.Scored != 2 || len(res.TopFindings) != 2 {
		t.Fatalf("counts = %+v scored=%d top=%d", res.Counts, res.Scored, len(res.TopFindings))
	}
	top := res.TopFindings[0]
	// 100 × (0.40·0.75 + 0.35·0.6 + 0.25·1) × R(unknown 0.7) × X(internet 1.0) = 53.2 → P2.
	if top.VulnID != "CVE-2022-32149" || top.Tier != risk.TierP2 || top.Score != 53.2 || top.PURL != "pkg:golang/golang.org/x/text@v0.3.7" ||
		!strings.Contains(top.Reason, "KEV") {
		t.Fatalf("top finding = %+v", top)
	}
	if res.TopFindings[1].Tier != risk.TierP3 || res.Tiers[risk.TierP2] != 1 || res.Tiers[risk.TierP3] != 1 || res.Tiers[risk.TierP1] != 0 {
		t.Fatalf("tiers = %+v, second = %+v", res.Tiers, res.TopFindings[1])
	}
	// Provenance comes from the claims.
	p, r := st.projects[0], st.runs[0]
	if p.RepoID != 101 || p.OwnerID != 202 || p.RepoFullName != "octo/demo" {
		t.Errorf("project = %+v", p)
	}
	if r.RunID != 4242 || r.RunAttempt != 2 || r.SHA != testSHA || r.Event != "push" || r.ActorID != 583231 ||
		!json.Valid(r.OIDCClaims) || !strings.Contains(string(r.OIDCClaims), `"repository_id":"101"`) {
		t.Errorf("run = %+v", r)
	}
	// Raw evidence is stored verbatim.
	if !bytes.Equal(st.evidence[0].Body, fixture(t, "grype-image-handbuilt.json")) || st.evidence[0].Tool.Version == "" {
		t.Errorf("stored evidence differs from the upload")
	}
	// Explanations are the risk engine's results.
	for id, rk := range st.risks {
		var expl risk.Result
		if err := json.Unmarshal(rk.Explanation, &expl); err != nil || expl.Scorer != risk.ScorerRisk || len(expl.Factors) == 0 ||
			expl.Score != rk.Score || string(expl.Tier) != string(rk.Tier) {
			t.Errorf("risk of %d = %+v (%v)", id, expl, err)
		}
	}
	// Audit entry.
	if len(st.audits) != 1 {
		t.Fatalf("audits = %d", len(st.audits))
	}
	a := st.audits[0]
	if a.Actor != "github-repo:101" || a.Action != "evidence.ingest" || a.Target != "artifact:"+testDigest || a.ProjectID != 1 ||
		!strings.Contains(string(a.Details), `"run_id":4242`) {
		t.Errorf("audit = %+v %s", a, a.Details)
	}
	if !strings.Contains(logs.String(), `"msg":"evidence ingested"`) || strings.Contains(logs.String(), "matches") {
		t.Errorf("logs = %s", logs.String())
	}

	// A replay is idempotent at the store; the result reports Created=false.
	res2, err := svc.Ingest(t.Context(), testClaims(), imageRequest(fixture(t, "grype-image-handbuilt.json")))
	if err != nil || res2.Evidence.Created || res2.Counts.FindingsSeen != 2 {
		t.Fatalf("replay = %+v, %v", res2, err)
	}
}

func TestIngestScoringRules(t *testing.T) {
	t.Parallel()
	st := newFakeStore()
	svc := newService(t, st, Options{Exposure: risk.ExposureBuild})
	doc := fixture(t, "govulncheck-source.json")
	// Pre-assign statuses: one VEX-suppressed (with the stored statement), one accepted.
	st.statuses["vexed"] = store.StatusVEXNotAffected
	req := imageRequest(doc)
	req.Format = evidence.FormatGovulncheck
	res, err := svc.Ingest(t.Context(), testClaims(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Scored != 3 || len(res.Warnings) != 0 {
		t.Fatalf("scored %d, warnings %v", res.Scored, res.Warnings)
	}
	// Now mark one finding suppressed by VEX and another accepted, then re-ingest.
	var suppressed, accepted int64
	for id, r := range st.findings {
		switch r.Finding.Vulnerability.ID {
		case "CVE-2023-39325":
			suppressed = id
			st.statuses[r.Finding.Fingerprint] = store.StatusVEXNotAffected
			st.vex[id] = evidence.VEXStatement{VulnID: "CVE-2023-39325", Products: []string{r.Finding.Component.PURL},
				Status: evidence.VEXNotAffected, Justification: "vulnerable_code_not_present"}
		case "CVE-2026-25681":
			accepted = id
			st.statuses[r.Finding.Fingerprint] = store.StatusAccepted
		}
	}
	before := st.risks[accepted]
	res, err = svc.Ingest(t.Context(), testClaims(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Scored != 2 {
		t.Fatalf("scored %d, want 2 (accepted findings are not re-scored)", res.Scored)
	}
	if got := st.risks[suppressed]; got.Score != 0 || got.Tier != store.TierP3 || !strings.Contains(string(got.Explanation), "vex-suppressed") {
		t.Errorf("suppressed risk = %+v %s", got, got.Explanation)
	}
	if !bytes.Equal(st.risks[accepted].Explanation, before.Explanation) {
		t.Error("accepted finding was re-scored")
	}
	// The suppressed finding ranks last.
	if last := res.TopFindings[len(res.TopFindings)-1]; last.ID != suppressed || last.Status != store.StatusVEXNotAffected {
		t.Errorf("ranking = %+v", res.TopFindings)
	}
}

func TestIngestCodeFindingsAreNotScored(t *testing.T) {
	t.Parallel()
	st := newFakeStore()
	svc := newService(t, st, Options{})
	req := imageRequest(fixture(t, "sarif-gosec.json"))
	req.Artifact.Kind = evidence.ArtifactSource
	res, err := svc.Ingest(t.Context(), testClaims(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Scored != 0 || len(res.TopFindings) != 0 || res.Counts.FindingsNew == 0 || len(st.risks) != 0 {
		t.Fatalf("result = %+v", res)
	}
}

func TestIngestSubjectDigestWarning(t *testing.T) {
	t.Parallel()
	svc := newService(t, newFakeStore(), Options{})
	req := imageRequest(fixture(t, "grype-image-handbuilt.json"))
	req.Artifact.Digest = "sha256:" + strings.Repeat("ab", 32)
	res, err := svc.Ingest(t.Context(), testClaims(), req)
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "differs from artifact.digest") {
		t.Fatalf("result = %+v, %v", res, err)
	}
}

func TestIngestVEXProductsExpanded(t *testing.T) {
	t.Parallel()
	st := newFakeStore()
	svc := newService(t, st, Options{})
	captured := &capturingStore{fakeStore: st}
	svc.store = captured
	if _, err := svc.Ingest(t.Context(), testClaims(), imageRequest(fixture(t, "openvex-govulncheck.json"))); err != nil {
		t.Fatal(err)
	}
	if len(captured.doc.VEX) != 3 {
		t.Fatalf("VEX = %+v", captured.doc.VEX)
	}
	for _, v := range captured.doc.VEX {
		if !slices.ContainsFunc(v.Products, func(p string) bool { return strings.HasPrefix(p, "pkg:golang/golang.org/x/") }) {
			t.Errorf("statement %s products %v lack the canonical package URL", v.VulnID, v.Products)
		}
	}
	if _, err := svc.Ingest(t.Context(), testClaims(), imageRequest(fixture(t, "openvex-handbuilt.json"))); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(captured.doc.VEX[0].Products, testDigest) {
		t.Errorf("pkg:oci product not expanded to its digest: %v", captured.doc.VEX[0].Products)
	}
}

type capturingStore struct {
	*fakeStore
	doc evidence.Document
}

func (c *capturingStore) IngestDocument(ctx context.Context, runID, artifactID int64, doc evidence.Document) (store.IngestResult, error) {
	c.doc = doc
	return c.fakeStore.IngestDocument(ctx, runID, artifactID, doc)
}

func TestIngestRejections(t *testing.T) {
	t.Parallel()
	grype := fixture(t, "grype-image-handbuilt.json")
	mutate := func(f func(*Request, *ghoidc.Claims)) (Request, *ghoidc.Claims) {
		r, c := imageRequest(grype), testClaims()
		f(&r, c)
		return r, c
	}
	tests := []struct {
		name   string
		req    func() (Request, *ghoidc.Claims)
		max    int64
		want   Kind
		detail string
	}{
		{"nil claims", func() (Request, *ghoidc.Claims) { return imageRequest(grype), nil }, 0, KindInternal, "identity"},
		{"bad kind", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Artifact.Kind = "vm" })
		}, 0, KindInvalidRequest, "artifact.kind"},
		{"tag instead of digest", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Artifact.Digest = "latest" })
		}, 0, KindInvalidRequest, "artifact.digest"},
		{"uppercase digest", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Artifact.Digest = strings.ToUpper(testDigest) })
		}, 0, KindInvalidRequest, "artifact.digest"},
		{"empty name", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Artifact.Name = "" })
		}, 0, KindInvalidRequest, "artifact.name"},
		{"control char name", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Artifact.Name = "a\nb" })
		}, 0, KindInvalidRequest, "artifact.name"},
		{"bad commit", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Commit = "main" })
		}, 0, KindInvalidRequest, "commit"},
		{"commit mismatch", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Commit = strings.Repeat("f", 40) })
		}, 0, KindForbidden, "sha claim"},
		{"bad format", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Format = "xml" })
		}, 0, KindInvalidRequest, "format"},
		{"empty evidence", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Evidence = nil })
		}, 0, KindInvalidRequest, "empty"},
		{"too large", func() (Request, *ghoidc.Claims) { return imageRequest(grype), testClaims() }, 100, KindTooLarge, "exceeds"},
		{"unknown format", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Evidence = []byte(`{"hello":"world"}`) })
		}, 0, KindUnprocessable, "unknown evidence format"},
		{"declared format mismatch", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) { r.Format = evidence.FormatSPDX })
		}, 0, KindUnprocessable, ""},
		{"deeply nested", func() (Request, *ghoidc.Claims) {
			return mutate(func(r *Request, _ *ghoidc.Claims) {
				r.Format = evidence.FormatGrype
				r.Evidence = []byte(`{"matches":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`)
			})
		}, 0, KindTooLarge, ""},
		{"bad repository id", func() (Request, *ghoidc.Claims) {
			return mutate(func(_ *Request, c *ghoidc.Claims) { c.RepositoryID = "x" })
		}, 0, KindInvalidRequest, "repository_id"},
		{"bad run attempt", func() (Request, *ghoidc.Claims) {
			return mutate(func(_ *Request, c *ghoidc.Claims) { c.RunAttempt = "1001" })
		}, 0, KindInvalidRequest, "run_attempt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := newFakeStore()
			svc := newService(t, st, Options{MaxEvidenceBytes: tt.max})
			req, claims := tt.req()
			_, err := svc.Ingest(t.Context(), claims, req)
			if KindOf(err) != tt.want {
				t.Fatalf("Ingest() = %v (kind %s), want kind %s", err, KindOf(err), tt.want)
			}
			if e, ok := errors.AsType[*Error](err); !ok || !strings.Contains(e.Detail, tt.detail) {
				t.Errorf("detail = %v, want %q", err, tt.detail)
			}
			if len(st.evidence) != 0 || len(st.projects) != 0 {
				t.Error("a rejected request wrote to the store")
			}
		})
	}
}

func TestIngestStoreErrors(t *testing.T) {
	t.Parallel()
	grype := fixture(t, "grype-image-handbuilt.json")
	tests := []struct {
		method string
		err    error
		want   Kind
		detail string
	}{
		{"UpsertProject", fmt.Errorf("store: upsert project: %w", store.ErrInvalidInput), KindUnprocessable, "invalid input"},
		{"RecordRun", fmt.Errorf("%w: run 1 attempt 1 is already recorded with a different sha", store.ErrConflict), KindConflict, "different sha"},
		{"UpsertArtifact", fmt.Errorf("store: x: %w: ERROR: violates check (SQLSTATE 23514)", store.ErrInvalidInput), KindUnprocessable, "rejected by the database"},
		{"AppendEvidence", errors.New("connection refused"), KindInternal, "storing the evidence failed"},
		{"IngestDocument", fmt.Errorf("x: %w", store.ErrNotFound), KindConflict, "not found"},
		{"GetFindings", context.Canceled, KindInternal, "cancelled"},
		{"ApplicableVEX", errors.New("boom"), KindInternal, "findings"},
		{"UpdateFindingRisks", context.DeadlineExceeded, KindInternal, "cancelled"},
		{"AppendAudit", errors.New("boom"), KindInternal, "audit"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			st := newFakeStore()
			st.err[tt.method] = tt.err
			svc := newService(t, st, Options{})
			_, err := svc.Ingest(t.Context(), testClaims(), imageRequest(grype))
			if KindOf(err) != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("Ingest() = %v (kind %s), want %s wrapping %v", err, KindOf(err), tt.want, tt.err)
			}
			if e, _ := errors.AsType[*Error](err); !strings.Contains(e.Detail, tt.detail) || strings.Contains(e.Detail, "SQLSTATE") {
				t.Errorf("detail = %q, want %q", e.Detail, tt.detail)
			}
		})
	}
}

func TestErrorHelpers(t *testing.T) {
	t.Parallel()
	for k, want := range map[Kind]string{
		KindInternal: "internal", KindInvalidRequest: "invalid_request", KindForbidden: "forbidden",
		KindUnprocessable: "unprocessable", KindTooLarge: "too_large", KindConflict: "conflict",
	} {
		if k.String() != want {
			t.Errorf("%d.String() = %q", k, k.String())
		}
	}
	if KindOf(errors.New("x")) != KindInternal {
		t.Error("plain error is not internal")
	}
	e := fail(KindConflict, nil, "d")
	if e.Error() != "ingest: conflict: d" || e.Unwrap() != nil {
		t.Errorf("Error() = %q", e.Error())
	}
	if got := safeDetail("a\x00b\nc\xff" + strings.Repeat("é", 600)); strings.ContainsAny(got, "\x00\n") ||
		len(got) > maxDetailLen+len("…") || !strings.HasPrefix(got, "a b c�") {
		t.Errorf("safeDetail = %q", got)
	}
}

func TestOCIDigest(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"pkg:oci/demo@sha256%3A" + strings.Repeat("ab", 32):                       "sha256:" + strings.Repeat("ab", 32),
		"pkg:oci/demo@sha256%3A" + strings.Repeat("AB", 32) + "?repository_url=x": "sha256:" + strings.Repeat("ab", 32),
		"pkg:oci/demo@latest":      "",
		"pkg:oci/demo":             "",
		"pkg:oci/demo@sha256%3Azz": "",
		"pkg:oci/demo@%zz":         "",
		"pkg:golang/x@sha256%3A" + strings.Repeat("ab", 32): "",
	} {
		if got := ociDigest(in); got != want {
			t.Errorf("ociDigest(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStorableJSON(t *testing.T) {
	t.Parallel()
	if b, wrapped, err := storableJSON([]byte(` {"a":1} `)); err != nil || wrapped || string(b) != ` {"a":1} ` {
		t.Errorf("single document = %q %v %v", b, wrapped, err)
	}
	b, wrapped, err := storableJSON([]byte("{\"config\":{}}\n{\"osv\": {\"id\":\"GO-1\"}}\n"))
	if err != nil || !wrapped || string(b) != `[{"config":{}},{"osv": {"id":"GO-1"}}]` || !json.Valid(b) {
		t.Errorf("stream = %q %v %v", b, wrapped, err)
	}
	if _, _, err := storableJSON([]byte(`{"a":1} {`)); err == nil {
		t.Error("truncated stream accepted")
	}
	// The govulncheck fixture is a stream: the response says so and keeps the upload hash.
	svc := newService(t, newFakeStore(), Options{})
	res, err := svc.Ingest(t.Context(), testClaims(), imageRequest(fixture(t, "govulncheck-source.json")))
	if err != nil || !res.Evidence.StreamWrapped || res.Evidence.UploadSHA256 != sha256Hex(fixture(t, "govulncheck-source.json")) {
		t.Fatalf("govulncheck = %+v, %v", res.Evidence, err)
	}
}
