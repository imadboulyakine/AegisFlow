package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/auth/ghoidc"
	"github.com/imadboulyakine/aegisflow/internal/config"
	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/ingest"
	"github.com/imadboulyakine/aegisflow/internal/ingest/ingesttest"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

const (
	p2SHA    = "0123456789abcdef0123456789abcdef01234567"
	p2Digest = "sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99"
	p2Aud    = "aegisflow-test"
)

func newP2Server(t *testing.T, mutate func(*config.Config), opts Options) (*Server, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	opts.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts.Version = testVersion
	cfg := config.Config{Addr: "127.0.0.1:0", LogLevel: slog.LevelDebug, ShutdownTimeout: 2 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	s.ready.Store(true)
	return s, logs
}

// fakeIngester records calls and returns a canned result or error.
type fakeIngester struct {
	mu     sync.Mutex
	calls  []ingest.Request
	claims []*ghoidc.Claims
	res    ingest.Result
	err    error
}

func (f *fakeIngester) Ingest(_ context.Context, c *ghoidc.Claims, req ingest.Request) (ingest.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	f.claims = append(f.claims, c)
	return f.res, f.err
}

func envelope(t *testing.T, evidenceBytes []byte, extra map[string]any) []byte {
	t.Helper()
	m := map[string]any{
		"artifact": map[string]string{"kind": "container-image", "name": "ghcr.io/octo/demo", "digest": p2Digest},
		"commit":   p2SHA,
		"evidence": base64.StdEncoding.EncodeToString(evidenceBytes),
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func post(t *testing.T, h http.Handler, target, contentType string, body []byte, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != contentTypeProblem {
		t.Fatalf("Content-Type = %q, want problem JSON (status %d, body %s)", ct, rec.Code, rec.Body.String())
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIngestDisabled(t *testing.T) {
	t.Parallel()
	s, _ := newP2Server(t, nil, Options{Static: testFS()})
	rec := post(t, s.Handler(), ingestPath, contentTypeJSON, envelope(t, []byte(`{}`), nil), nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if p := decodeProblem(t, rec); !strings.Contains(p.Detail, "not configured") || p.RequestID == "" || p.Instance != ingestPath {
		t.Errorf("problem = %+v", p)
	}
	if rec := do(t, s.Handler(), http.MethodGet, ingestPath, nil); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET ingest = %d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestIngestThroughOIDCMiddleware(t *testing.T) {
	t.Parallel()
	iss := ingesttest.NewIssuer(t)
	v, err := ghoidc.NewVerifier(ghoidc.Config{Issuer: iss.URL, Audience: p2Aud, AllowedRepositoryIDs: []int64{101}})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeIngester{res: ingest.Result{ProjectID: 1, Evidence: ingest.EvidenceSummary{ID: 9, Created: true}}}
	s, logs := newP2Server(t, nil, Options{Static: testFS(), Verifier: v, Ingester: fake})
	h := s.Handler()
	body := envelope(t, []byte(`{"bomFormat":"CycloneDX"}`), map[string]any{"format": "cyclonedx"})

	// No token.
	rec := post(t, h, ingestPath, contentTypeJSON, body, nil)
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("no token = %d %v", rec.Code, rec.Header())
	}
	if p := decodeProblem(t, rec); p.RequestID == "" || p.Instance != ingestPath {
		t.Errorf("auth problem lacks the server's request ID: %+v", p)
	}
	// Repository not allowed.
	other := iss.Mint(t, iss.Claims(p2Aud, 999, 202, p2SHA))
	if rec := post(t, h, ingestPath, contentTypeJSON, body, http.Header{"Authorization": {"Bearer " + other}}); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign repository = %d", rec.Code)
	}
	if len(fake.calls) != 0 {
		t.Fatal("ingester called without a valid token")
	}
	// Valid token.
	token := iss.Mint(t, iss.Claims(p2Aud, 101, 202, p2SHA))
	rec = post(t, h, ingestPath, contentTypeJSON, body, http.Header{"Authorization": {"Bearer " + token}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid token = %d %s", rec.Code, rec.Body.String())
	}
	var res ingest.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.Evidence.ID != 9 {
		t.Fatalf("body = %s (%v)", rec.Body.String(), err)
	}
	if len(fake.calls) != 1 || fake.claims[0].RepositoryID != "101" || fake.calls[0].Format != evidence.FormatCycloneDX ||
		string(fake.calls[0].Evidence) != `{"bomFormat":"CycloneDX"}` || fake.calls[0].Artifact.Digest != p2Digest {
		t.Fatalf("ingester got %+v / %+v", fake.calls, fake.claims)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("token leaked into logs")
	}
	// Idempotent replay answers 200.
	fake.res.Evidence.Created = false
	if rec := post(t, h, ingestPath, contentTypeJSON, body, http.Header{"Authorization": {"Bearer " + token}}); rec.Code != http.StatusOK {
		t.Fatalf("replay = %d", rec.Code)
	}
}

func TestIngestBodyLimits(t *testing.T) {
	t.Parallel()
	read := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("x", int(n%7)))
	})
	h := limitBody(read)
	big := bytes.Repeat([]byte("a"), maxBodyBytes+1)
	for _, tc := range []struct {
		method, path string
		size         int
		want         int
	}{
		{http.MethodPost, ingestPath, maxBodyBytes + 1, http.StatusOK},
		{http.MethodPost, ingestPath, maxIngestBodyBytes, http.StatusOK},
		{http.MethodPost, ingestPath, maxIngestBodyBytes + 1, http.StatusRequestEntityTooLarge},
		{http.MethodPut, ingestPath, maxBodyBytes + 1, http.StatusRequestEntityTooLarge},
		{http.MethodPost, "/api/v1/ingest/", maxBodyBytes + 1, http.StatusRequestEntityTooLarge},
		{http.MethodPost, "/api/v1/other", maxBodyBytes + 1, http.StatusRequestEntityTooLarge},
		{http.MethodPost, "/api/v1/other", maxBodyBytes, http.StatusOK},
	} {
		body := big
		if tc.size != len(big) {
			body = bytes.Repeat([]byte("a"), tc.size)
		}
		req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %s (%d bytes) = %d, want %d", tc.method, tc.path, tc.size, rec.Code, tc.want)
		}
	}
}

func TestHandleIngestEnvelope(t *testing.T) {
	t.Parallel()
	ev := []byte(`{"matches":[]}`)
	tests := []struct {
		name        string
		contentType string
		body        []byte
		err         error
		want        int
		detail      string
	}{
		{"ok", "application/json; charset=utf-8", envelope(t, ev, nil), nil, http.StatusOK, ""},
		{"with sha", contentTypeJSON, envelope(t, ev, map[string]any{"evidenceSha256": "9C1E" + strings.Repeat("0", 60)}), nil, http.StatusUnprocessableEntity, "evidenceSha256"},
		{"wrong content type", "text/plain", envelope(t, ev, nil), nil, http.StatusUnsupportedMediaType, "application/json"},
		{"no content type", "", envelope(t, ev, nil), nil, http.StatusUnsupportedMediaType, ""},
		{"malformed", contentTypeJSON, []byte(`{"artifact":`), nil, http.StatusBadRequest, "truncated"},
		{"syntax", contentTypeJSON, []byte(`{"artifact" 1}`), nil, http.StatusBadRequest, "malformed JSON"},
		{"empty", contentTypeJSON, nil, nil, http.StatusBadRequest, "empty"},
		{"unknown field", contentTypeJSON, envelope(t, ev, map[string]any{"token": "x"}), nil, http.StatusBadRequest, `unknown field "token"`},
		{"wrong type", contentTypeJSON, envelope(t, ev, map[string]any{"commit": 5}), nil, http.StatusBadRequest, "commit has the wrong type"},
		{"trailing data", contentTypeJSON, append(envelope(t, ev, nil), []byte(` {}`)...), nil, http.StatusBadRequest, "single JSON object"},
		{"no artifact", contentTypeJSON, envelope(t, ev, map[string]any{"artifact": nil}), nil, http.StatusBadRequest, "artifact is required"},
		{"no evidence", contentTypeJSON, envelope(t, ev, map[string]any{"evidence": ""}), nil, http.StatusBadRequest, "evidence"},
		{"bad base64", contentTypeJSON, envelope(t, ev, map[string]any{"evidence": "!!!"}), nil, http.StatusBadRequest, "base64"},
		{"unpadded base64", contentTypeJSON, envelope(t, ev, map[string]any{"evidence": "e30"}), nil, http.StatusBadRequest, "base64"},
		{"invalid request", contentTypeJSON, envelope(t, ev, nil), &ingest.Error{Kind: ingest.KindInvalidRequest, Detail: "artifact.kind bad"}, http.StatusBadRequest, "artifact.kind bad"},
		{"forbidden", contentTypeJSON, envelope(t, ev, nil), &ingest.Error{Kind: ingest.KindForbidden, Detail: "commit mismatch"}, http.StatusForbidden, "commit mismatch"},
		{"unprocessable", contentTypeJSON, envelope(t, ev, nil), &ingest.Error{Kind: ingest.KindUnprocessable, Detail: "unknown format"}, http.StatusUnprocessableEntity, "unknown format"},
		{"too large", contentTypeJSON, envelope(t, ev, nil), &ingest.Error{Kind: ingest.KindTooLarge, Detail: "limit"}, http.StatusRequestEntityTooLarge, "limit"},
		{"conflict", contentTypeJSON, envelope(t, ev, nil), &ingest.Error{Kind: ingest.KindConflict, Detail: "other sha"}, http.StatusConflict, "other sha"},
		{"internal", contentTypeJSON, envelope(t, ev, nil), &ingest.Error{Kind: ingest.KindInternal, Detail: "db password=hunter2"}, http.StatusInternalServerError, "unexpected error"},
		{"plain error", contentTypeJSON, envelope(t, ev, nil), errors.New("boom"), http.StatusInternalServerError, "unexpected error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeIngester{err: tt.err}
			s, _ := newP2Server(t, nil, Options{Static: testFS(), Ingester: fake})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, ingestPath, bytes.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			req = req.WithContext(ghoidc.ContextWithClaims(req.Context(), &ghoidc.Claims{RepositoryID: "101", SHA: p2SHA}))
			rec := httptest.NewRecorder()
			s.handleIngest(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusOK {
				if len(fake.calls) != 1 || string(fake.calls[0].Evidence) != string(ev) {
					t.Fatalf("calls = %+v", fake.calls)
				}
				return
			}
			p := decodeProblem(t, rec)
			if !strings.Contains(p.Detail, tt.detail) || strings.Contains(p.Detail, "hunter2") {
				t.Errorf("detail = %q, want %q", p.Detail, tt.detail)
			}
		})
	}

	t.Run("no claims", func(t *testing.T) {
		t.Parallel()
		s, _ := newP2Server(t, nil, Options{Static: testFS(), Ingester: &fakeIngester{}})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, ingestPath, bytes.NewReader(envelope(t, ev, nil)))
		rec := httptest.NewRecorder()
		s.handleIngest(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("matching sha", func(t *testing.T) {
		t.Parallel()
		req, status, _ := decodeIngest(bytes.NewReader(envelope(t, []byte("{}"), map[string]any{
			"evidenceSha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		})))
		if status != 0 || string(req.Evidence) != "{}" {
			t.Fatalf("status = %d", status)
		}
	})
	t.Run("max bytes", func(t *testing.T) {
		t.Parallel()
		big := bytes.NewReader(envelope(t, bytes.Repeat([]byte("a"), 2048), nil))
		r := http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(big), 100)
		if _, status, _ := decodeIngest(r); status != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d", status)
		}
		// Limit hit while checking for trailing data.
		body := envelope(t, []byte("{}"), nil)
		r = http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(bytes.NewReader(append(body, []byte("      ")...))), int64(len(body)+1))
		if _, status, _ := decodeIngest(r); status != http.StatusRequestEntityTooLarge {
			t.Fatalf("trailing status = %d", status)
		}
	})
}

// fakeFindings is an in-memory FindingsReader.
type fakeFindings struct {
	page    store.FindingPage
	rec     store.FindingRecord
	err     error
	filters []store.FindingFilter
	mu      sync.Mutex
}

func (f *fakeFindings) ListFindings(_ context.Context, filter store.FindingFilter) (store.FindingPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, filter)
	return f.page, f.err
}

func (f *fakeFindings) GetFinding(_ context.Context, id int64) (store.FindingRecord, error) {
	if f.err != nil {
		return store.FindingRecord{}, f.err
	}
	if id != f.rec.ID {
		return store.FindingRecord{}, store.ErrNotFound
	}
	return f.rec, nil
}

func sampleRecord() store.FindingRecord {
	expl := `{"scorer":"aegisflow-risk/v1","score":76,"tier":"P1","action":"block","flags":["kev-override"],` +
		`"factors":[{"name":"cvss","kind":"additive","raw":"7.5","normalized":0.75,"weight":0.4,"contribution":30,"source":"CVSS v3.1"}],` +
		`"reason":"P1: CVSS 7.5, in CISA KEV"}`
	return store.FindingRecord{
		ID: 7, ArtifactID: 3, Status: store.StatusOpen, FirstSeenRun: 1, LastSeenRun: 2,
		UpdatedAt: time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC),
		Finding: evidence.Finding{
			Kind: evidence.FindingVulnerability, Fingerprint: "fp", Title: "x/text DoS", Message: "long message",
			Severity: evidence.SeverityHigh, Tools: []evidence.Tool{{Name: "grype"}, {Name: "govulncheck"}},
			Reachability: evidence.ReachabilityCalled,
			Vulnerability: &evidence.Vulnerability{
				ID: "CVE-2022-32149", Aliases: []string{"GO-2022-1059"}, Summary: "summary", Severity: evidence.SeverityHigh,
				CVSS: []evidence.CVSS{{Version: "3.1", BaseScore: 7.5}}, CWEs: []string{"CWE-772"},
				Published: time.Date(2022, 10, 14, 0, 0, 0, 0, time.UTC),
			},
			Component: &evidence.Component{PURL: "pkg:golang/golang.org/x/text@v0.3.7", Name: "golang.org/x/text", Version: "v0.3.7", Ecosystem: "golang", Direct: true},
		},
		Risk: &store.Risk{Score: 76, Tier: store.TierP1, Explanation: json.RawMessage(expl), ScoredAt: time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)},
	}
}

func getFrom(t *testing.T, h http.Handler, target, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestReadAPIGuard(t *testing.T) {
	t.Parallel()
	devOn := func(c *config.Config) { c.DevReadOnlyAPI = true }
	off, _ := newP2Server(t, nil, Options{Static: testFS(), Findings: &fakeFindings{}})
	on, _ := newP2Server(t, devOn, Options{Static: testFS(), Findings: &fakeFindings{}})
	noDB, _ := newP2Server(t, devOn, Options{Static: testFS()})
	for _, tc := range []struct {
		name   string
		s      *Server
		remote string
		want   int
	}{
		{"disabled by default", off, "127.0.0.1:5000", http.StatusNotFound},
		{"remote client", on, "192.0.2.10:5000", http.StatusForbidden},
		{"private client", on, "10.0.0.5:5000", http.StatusForbidden},
		{"garbage remote", on, "nonsense", http.StatusForbidden},
		{"ipv4 loopback", on, "127.0.0.1:5000", http.StatusOK},
		{"ipv6 loopback", on, "[::1]:5000", http.StatusOK},
		{"mapped loopback", on, "[::ffff:127.0.0.1]:5000", http.StatusOK},
		{"no database", noDB, "127.0.0.1:5000", http.StatusServiceUnavailable},
	} {
		for _, path := range []string{"/api/v1/findings", "/api/v1/findings/7"} {
			rec := getFrom(t, tc.s.Handler(), path, tc.remote)
			want := tc.want
			if want == http.StatusOK && path != "/api/v1/findings" {
				want = http.StatusNotFound // fakeFindings has no record 7
			}
			if rec.Code != want {
				t.Errorf("%s %s = %d, want %d", tc.name, path, rec.Code, want)
			}
			if rec.Code != http.StatusOK {
				decodeProblem(t, rec)
			}
		}
	}
}

func TestListFindings(t *testing.T) {
	t.Parallel()
	ff := &fakeFindings{page: store.FindingPage{Findings: []store.FindingRecord{sampleRecord(), {
		ID: 6, ArtifactID: 3, Status: store.StatusOpen,
		Finding: evidence.Finding{Kind: evidence.FindingCode, Title: "G104", Severity: evidence.SeverityLow, RuleID: "G104",
			Tools: []evidence.Tool{{Name: "gosec"}}, Location: &evidence.Location{Path: "main.go", StartLine: 3}},
	}}, NextCursor: "next"}}
	s, _ := newP2Server(t, func(c *config.Config) { c.DevReadOnlyAPI = true }, Options{Static: testFS(), Findings: ff})
	rec := getFrom(t, s.Handler(), "/api/v1/findings?tier=P1&status=open&kind=vulnerability&artifact=3&limit=10&cursor=abc", "127.0.0.1:1")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	got := ff.filters[0]
	if got.Tier != store.TierP1 || got.Status != store.StatusOpen || got.Kind != evidence.FindingVulnerability ||
		got.ArtifactID != 3 || got.Limit != 10 || got.Cursor != "abc" || got.ProjectID != 0 {
		t.Errorf("filter = %+v", got)
	}
	var page struct {
		Findings []map[string]any `json:"findings"`
		Next     string           `json:"nextCursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Findings) != 2 || page.Next != "next" {
		t.Fatalf("page = %s (%v)", rec.Body.String(), err)
	}
	f0 := page.Findings[0]
	riskObj := f0["risk"].(map[string]any)
	if riskObj["tier"] != "P1" || riskObj["reason"] != "P1: CVSS 7.5, in CISA KEV" || riskObj["action"] != "block" ||
		riskObj["explanation"] != nil || f0["message"] != nil || f0["reachability"] != "called" {
		t.Errorf("listing item = %v", f0)
	}
	if v := f0["vulnerability"].(map[string]any); v["id"] != "CVE-2022-32149" || v["cvss"] != nil {
		t.Errorf("listing vulnerability = %v", v)
	}
	if f1 := page.Findings[1]; f1["risk"] != nil || f1["vulnerability"] != nil || f1["component"] != nil || f1["reachability"] != "" {
		t.Errorf("code finding = %v", f1)
	}

	for _, q := range []string{"?tier=P4", "?status=closed", "?kind=sast", "?artifact=0", "?artifact=x", "?limit=0",
		"?limit=501", "?limit=x", "?project=1", "?tier=P1&tier=P2"} {
		if rec := getFrom(t, s.Handler(), "/api/v1/findings"+q, "127.0.0.1:1"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, rec.Code)
		} else {
			decodeProblem(t, rec)
		}
	}
	ff.err = store.ErrInvalidInput
	if rec := getFrom(t, s.Handler(), "/api/v1/findings?cursor=bad", "127.0.0.1:1"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad cursor = %d", rec.Code)
	}
	ff.err = errors.New("connection reset")
	if rec := getFrom(t, s.Handler(), "/api/v1/findings", "127.0.0.1:1"); rec.Code != http.StatusInternalServerError ||
		strings.Contains(rec.Body.String(), "connection reset") {
		t.Errorf("store failure = %d %s", rec.Code, rec.Body.String())
	}
}

func TestGetFinding(t *testing.T) {
	t.Parallel()
	ff := &fakeFindings{rec: sampleRecord()}
	s, _ := newP2Server(t, func(c *config.Config) { c.DevReadOnlyAPI = true }, Options{Static: testFS(), Findings: ff})
	rec := getFrom(t, s.Handler(), "/api/v1/findings/7", "127.0.0.1:1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	var f struct {
		Message       string `json:"message"`
		Vulnerability struct {
			CVSS      []evidence.CVSS `json:"cvss"`
			Published string          `json:"published"`
			Summary   string          `json:"summary"`
		} `json:"vulnerability"`
		Component struct {
			Direct bool `json:"direct"`
		} `json:"component"`
		Risk struct {
			Flags       []string `json:"flags"`
			Explanation struct {
				Factors []map[string]any `json:"factors"`
			} `json:"explanation"`
		} `json:"risk"`
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f.Message != "long message" || len(f.Vulnerability.CVSS) != 1 || f.Vulnerability.Summary != "summary" ||
		!strings.HasPrefix(f.Vulnerability.Published, "2022-10-14") || !f.Component.Direct ||
		len(f.Risk.Explanation.Factors) != 1 || len(f.Risk.Flags) != 1 || len(f.Tools) != 2 {
		t.Errorf("detail = %s", rec.Body.String())
	}
	for _, path := range []string{"/api/v1/findings/0", "/api/v1/findings/abc", "/api/v1/findings/99999999999999999999", "/api/v1/findings/8"} {
		if rec := getFrom(t, s.Handler(), path, "127.0.0.1:1"); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, rec.Code)
		}
	}
	// A corrupt explanation still renders (without the summary fields).
	bad := sampleRecord()
	bad.Risk.Explanation = json.RawMessage(`[]`)
	if got := toFindingJSON(bad, false); got.Risk.Reason != "" || got.Risk.Flags == nil {
		t.Errorf("corrupt explanation = %+v", got.Risk)
	}
}

func TestReadyzWithDependency(t *testing.T) {
	t.Parallel()
	var fail error
	var mu sync.Mutex
	ready := func(context.Context) error { mu.Lock(); defer mu.Unlock(); return fail }
	s, logs := newP2Server(t, nil, Options{Static: testFS(), Ready: ready})
	rec := do(t, s.Handler(), http.MethodGet, "/readyz", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"database":"ok"`) {
		t.Fatalf("ready = %d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	fail = errors.New("dial tcp: connection refused")
	mu.Unlock()
	rec = do(t, s.Handler(), http.MethodGet, "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"database":"unavailable"`) ||
		strings.Contains(rec.Body.String(), "refused") {
		t.Fatalf("not ready = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "readiness check failed") {
		t.Error("readiness failure not logged")
	}
	// /healthz stays dependency-free.
	if rec := do(t, s.Handler(), http.MethodGet, "/healthz", nil); rec.Code != http.StatusOK {
		t.Errorf("healthz = %d", rec.Code)
	}
}
