package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/config"
	"github.com/imadboulyakine/aegisflow/internal/version"
)

const (
	testIndex = `<!doctype html><html><head><script type="module" src="/assets/index-abcd1234.js"></script></head>` +
		`<body><div id="root"></div></body></html>`
	testJS = `console.log("aegisflow")`
)

var testVersion = version.Info{
	Version:   "v0.0.0-test",
	Commit:    "0123456789abcdef0123456789abcdef01234567",
	BuildDate: "2026-10-26T12:00:00Z",
	GoVersion: "go1.27.3",
}

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                  {Data: []byte(testIndex)},
		"assets/index-abcd1234.js":    {Data: []byte(testJS)},
		"assets/index-efgh5678.css":   {Data: []byte("body{margin:0}")},
		"assets/favicon-zz99yy88.svg": {Data: []byte("<svg/>")},
		"assets/notes.unknownext":     {Data: []byte{0, 1, 2}},
		"robots.txt":                  {Data: []byte("User-agent: *\nDisallow:\n")},
		".gitkeep":                    {Data: nil},
		".secret/config":              {Data: []byte("nope")},
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestServer(t *testing.T, opts Options) (*Server, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	if opts.Version == (version.Info{}) {
		opts.Version = testVersion
	}
	cfg := config.Config{Addr: "127.0.0.1:0", LogLevel: slog.LevelDebug, ShutdownTimeout: 2 * time.Second}
	s, err := New(cfg, opts)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return s, logs
}

func do(t *testing.T, h http.Handler, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRoutes(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{Static: testFS()})
	s.ready.Store(true)
	h := s.Handler()

	tests := []struct {
		name         string
		method       string
		target       string
		wantStatus   int
		wantType     string
		wantCache    string
		wantBody     string // substring
		wantNotBody  string // substring that must be absent
		wantAllow    string
		wantNoETag   bool
		wantImmutabl bool
	}{
		{name: "healthz", method: "GET", target: "/healthz", wantStatus: 200, wantType: "application/json", wantCache: "no-store", wantBody: `{"status":"ok"}`},
		{name: "healthz head", method: "HEAD", target: "/healthz", wantStatus: 200, wantType: "application/json"},
		{name: "healthz wrong method", method: "POST", target: "/healthz", wantStatus: 405, wantAllow: "GET, HEAD"},
		{name: "readyz", method: "GET", target: "/readyz", wantStatus: 200, wantType: "application/json", wantCache: "no-store", wantBody: `{"status":"ready"}`},
		{name: "version", method: "GET", target: "/api/v1/version", wantStatus: 200, wantType: "application/json", wantCache: "no-store", wantBody: `"commit":"0123456789abcdef0123456789abcdef01234567"`},
		{name: "version wrong method", method: "DELETE", target: "/api/v1/version", wantStatus: 405, wantType: "application/problem+json", wantAllow: "GET, HEAD", wantBody: `"status":405`},
		{name: "unknown api route", method: "GET", target: "/api/v1/nope", wantStatus: 404, wantType: "application/problem+json", wantCache: "no-store", wantBody: `"instance":"/api/v1/nope"`},
		{name: "unknown api version", method: "GET", target: "/api/v2/version", wantStatus: 404, wantType: "application/problem+json"},
		{name: "api root", method: "GET", target: "/api", wantStatus: 404, wantType: "application/problem+json"},
		{name: "api root slash", method: "GET", target: "/api/", wantStatus: 404, wantType: "application/problem+json"},
		{name: "api post unknown", method: "POST", target: "/api/v1/nope", wantStatus: 404, wantType: "application/problem+json"},
		{name: "spa root", method: "GET", target: "/", wantStatus: 200, wantType: "text/html; charset=utf-8", wantCache: "no-cache", wantBody: `src="/assets/index-abcd1234.js"`},
		{name: "spa index.html", method: "GET", target: "/index.html", wantStatus: 200, wantType: "text/html; charset=utf-8", wantCache: "no-cache", wantBody: `<div id="root">`},
		{name: "client route", method: "GET", target: "/vulnerabilities", wantStatus: 200, wantType: "text/html; charset=utf-8", wantCache: "no-cache", wantBody: `<div id="root">`},
		{name: "nested client route", method: "GET", target: "/vulnerabilities/CVE-2026-0001/", wantStatus: 200, wantType: "text/html; charset=utf-8", wantBody: `<div id="root">`},
		{name: "client route with query", method: "GET", target: "/policies?tab=active", wantStatus: 200, wantType: "text/html; charset=utf-8"},
		{name: "hashed js", method: "GET", target: "/assets/index-abcd1234.js", wantStatus: 200, wantType: "text/javascript; charset=utf-8", wantCache: "public, max-age=31536000, immutable", wantBody: testJS},
		{name: "hashed css", method: "GET", target: "/assets/index-efgh5678.css", wantStatus: 200, wantType: "text/css; charset=utf-8", wantCache: "public, max-age=31536000, immutable"},
		{name: "hashed svg", method: "GET", target: "/assets/favicon-zz99yy88.svg", wantStatus: 200, wantType: "image/svg+xml"},
		{name: "unknown extension", method: "GET", target: "/assets/notes.unknownext", wantStatus: 200, wantType: "application/octet-stream", wantCache: "no-cache"},
		{name: "unhashed root file", method: "GET", target: "/robots.txt", wantStatus: 200, wantType: "text/plain; charset=utf-8", wantCache: "no-cache"},
		{name: "missing asset is 404 not index", method: "GET", target: "/assets/index-00000000.js", wantStatus: 404, wantNotBody: "<html"},
		{name: "missing favicon", method: "GET", target: "/favicon.ico", wantStatus: 404},
		{name: "dotfile hidden", method: "GET", target: "/.gitkeep", wantStatus: 404},
		{name: "dot directory hidden", method: "GET", target: "/.secret/config", wantStatus: 404},
		{name: "spa post", method: "POST", target: "/", wantStatus: 405, wantAllow: "GET, HEAD"},
		{name: "spa head", method: "HEAD", target: "/vulnerabilities", wantStatus: 200, wantType: "text/html; charset=utf-8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, h, tt.method, tt.target, nil)
			res := rec.Result()
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", res.StatusCode, tt.wantStatus, rec.Body.String())
			}
			if tt.wantType != "" && res.Header.Get("Content-Type") != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", res.Header.Get("Content-Type"), tt.wantType)
			}
			if tt.wantCache != "" && res.Header.Get("Cache-Control") != tt.wantCache {
				t.Errorf("Cache-Control = %q, want %q", res.Header.Get("Cache-Control"), tt.wantCache)
			}
			if tt.wantAllow != "" && res.Header.Get("Allow") != tt.wantAllow {
				t.Errorf("Allow = %q, want %q", res.Header.Get("Allow"), tt.wantAllow)
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want substring %q", rec.Body.String(), tt.wantBody)
			}
			if tt.wantNotBody != "" && strings.Contains(rec.Body.String(), tt.wantNotBody) {
				t.Errorf("body = %q, must not contain %q", rec.Body.String(), tt.wantNotBody)
			}
			assertSecurityHeaders(t, res.Header)
			if res.Header.Get(HeaderRequestID) == "" {
				t.Error("missing X-Request-ID response header")
			}
		})
	}
}

func assertSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":      "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if !strings.Contains(h.Get("Permissions-Policy"), "camera=()") {
		t.Errorf("Permissions-Policy = %q, want camera disabled", h.Get("Permissions-Policy"))
	}
	if h.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must be set by the TLS-terminating ingress, not the app")
	}
}

func TestVersionPayload(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	rec := do(t, s.Handler(), "GET", "/api/v1/version", nil)
	var got version.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != testVersion {
		t.Errorf("version = %+v, want %+v", got, testVersion)
	}
}

func TestProblemBody(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	rec := do(t, s.Handler(), "GET", "/api/v1/missing", http.Header{HeaderRequestID: {"req-123"}})
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := problem{
		Type: "about:blank", Title: "Not Found", Status: 404,
		Detail: "No API resource matches this path.", Instance: "/api/v1/missing", RequestID: "req-123",
	}
	if p != want {
		t.Errorf("problem = %+v, want %+v", p, want)
	}
}

func TestReadinessReflectsState(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	rec := do(t, s.Handler(), "GET", "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not_ready") {
		t.Fatalf("before start: status=%d body=%q, want 503 not_ready", rec.Code, rec.Body.String())
	}
	s.ready.Store(true)
	if rec := do(t, s.Handler(), "GET", "/readyz", nil); rec.Code != http.StatusOK {
		t.Fatalf("after ready: status=%d, want 200", rec.Code)
	}
}

func TestConditionalRequests(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{Static: testFS()})
	h := s.Handler()
	for _, target := range []string{"/", "/assets/index-abcd1234.js"} {
		first := do(t, h, "GET", target, nil)
		etag := first.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("%s: missing ETag", target)
		}
		second := do(t, h, "GET", target, http.Header{"If-None-Match": {etag}})
		if second.Code != http.StatusNotModified {
			t.Errorf("%s: conditional GET status = %d, want 304", target, second.Code)
		}
	}
}

func TestFallbackPageWithoutFrontend(t *testing.T) {
	t.Parallel()

	for name, static := range map[string]fstest.MapFS{
		"nil fs":       nil,
		"only gitkeep": {".gitkeep": {}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var opts Options
			if static != nil {
				opts.Static = static
			}
			s, _ := newTestServer(t, opts)
			for _, target := range []string{"/", "/vulnerabilities"} {
				rec := do(t, s.Handler(), "GET", target, nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: status = %d, want 200", target, rec.Code)
				}
				body := rec.Body.String()
				if !strings.Contains(body, "make build") {
					t.Errorf("%s: fallback page missing build hint: %q", target, body)
				}
				if strings.Contains(body, "<script") || strings.Contains(body, "<style") || strings.Contains(body, "style=") {
					t.Errorf("%s: fallback page must be CSP-clean", target)
				}
			}
		})
	}
}

func TestNewRejectsUnreadableFS(t *testing.T) {
	t.Parallel()

	_, err := New(config.Config{Addr: ":0"}, Options{Static: brokenFS{}})
	if err == nil {
		t.Fatal("New() error = nil, want error for unreadable static FS")
	}
}

type brokenFS struct{}

func (brokenFS) Open(string) (fs.File, error) { return nil, errors.New("disk on fire") }

func TestRequestID(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	h := s.Handler()

	tests := []struct {
		name     string
		incoming string
		wantEcho bool
	}{
		{"absent", "", false},
		{"valid uuid", "8a5f1c2e-3b4d-4e6f-9a0b-1c2d3e4f5a6b", true},
		{"valid token chars", "abc_DEF.123-xyz", true},
		{"max length", strings.Repeat("a", maxRequestIDLen), true},
		{"too long", strings.Repeat("a", maxRequestIDLen+1), false},
		{"spaces", "abc def", false},
		{"log injection", "abc\",\"level\":\"ERROR", false},
		{"non ascii", "réquest", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var hdr http.Header
			if tt.incoming != "" {
				hdr = http.Header{HeaderRequestID: {tt.incoming}}
			}
			got := do(t, h, "GET", "/healthz", hdr).Header().Get(HeaderRequestID)
			if tt.wantEcho {
				if got != tt.incoming {
					t.Errorf("X-Request-ID = %q, want echo of %q", got, tt.incoming)
				}
				return
			}
			if got == tt.incoming || !validRequestID(got) || len(got) != 26 {
				t.Errorf("X-Request-ID = %q, want freshly generated 26-char ID", got)
			}
		})
	}
}

func TestRequestIDsAreUnique(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	seen := map[string]bool{}
	for range 100 {
		id := do(t, s.Handler(), "GET", "/healthz", nil).Header().Get(HeaderRequestID)
		if seen[id] {
			t.Fatalf("duplicate request ID %q", id)
		}
		seen[id] = true
	}
}

func TestRequestIDFromContext(t *testing.T) {
	t.Parallel()

	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("RequestIDFromContext(empty) = %q, want empty", got)
	}
	var seen string
	h := requestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	rec := do(t, h, "GET", "/", http.Header{HeaderRequestID: {"ctx-id"}})
	if seen != "ctx-id" || rec.Header().Get(HeaderRequestID) != "ctx-id" {
		t.Errorf("context ID = %q, header = %q, want ctx-id", seen, rec.Header().Get(HeaderRequestID))
	}
}

func TestPanicRecovery(t *testing.T) {
	t.Parallel()

	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	h := chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
		requestID, securityHeaders, accessLog(logger), recoverPanics(logger))

	rec := do(t, h, "GET", "/api/v1/explode", http.Header{HeaderRequestID: {"panic-req"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != contentTypeProblem {
		t.Errorf("Content-Type = %q, want %q", ct, contentTypeProblem)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Error("panic value leaked to the client")
	}
	assertSecurityHeaders(t, rec.Header())

	out := logs.String()
	for _, want := range []string{`"msg":"panic recovered"`, `"panic":"boom"`, `"stack":"goroutine`, `"request_id":"panic-req"`, `"status":500`} {
		if !strings.Contains(out, want) {
			t.Errorf("logs missing %s:\n%s", want, out)
		}
	}
}

func TestPanicDropsStaleRepresentationHeaders(t *testing.T) {
	t.Parallel()

	h := recoverPanics(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "3")
		w.Header().Set("ETag", `"stale"`)
		panic("before write")
	}))
	rec := do(t, h, "GET", "/", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if rec.Header().Get("Content-Length") != "" || rec.Header().Get("ETag") != "" {
		t.Errorf("stale headers survived: %v", rec.Header())
	}
}

func TestPanicAfterHeadersAborts(t *testing.T) {
	t.Parallel()

	h := recoverPanics(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		panic("late")
	}))
	assertPanicsWith(t, h, http.ErrAbortHandler)
}

func TestAbortHandlerPanicPropagates(t *testing.T) {
	t.Parallel()

	h := recoverPanics(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	assertPanicsWith(t, h, http.ErrAbortHandler)
}

func assertPanicsWith(t *testing.T, h http.Handler, want error) {
	t.Helper()
	defer func() {
		v := recover()
		err, ok := v.(error)
		if !ok || !errors.Is(err, want) {
			t.Fatalf("recovered %v, want panic with %v", v, want)
		}
	}()
	do(t, h, "GET", "/", nil)
}

func TestAccessLog(t *testing.T) {
	t.Parallel()

	s, logs := newTestServer(t, Options{Static: testFS()})
	h := s.Handler()
	do(t, h, "GET", "/vulnerabilities?token=s3cr3t", http.Header{HeaderRequestID: {"log-req"}, "User-Agent": {"test-agent"}})
	do(t, h, "GET", "/healthz", nil)

	var lines []map[string]any
	for line := range strings.Lines(logs.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		lines = append(lines, m)
	}
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2:\n%s", len(lines), logs.String())
	}
	first := lines[0]
	checks := map[string]any{
		"msg": "http request", "level": "INFO", "method": "GET", "path": "/vulnerabilities",
		"status": float64(200), "request_id": "log-req", "user_agent": "test-agent",
	}
	for k, v := range checks {
		if first[k] != v {
			t.Errorf("log[%s] = %v, want %v", k, first[k], v)
		}
	}
	if _, ok := first["duration_ms"]; !ok {
		t.Error("log missing duration_ms")
	}
	if strings.Contains(logs.String(), "s3cr3t") {
		t.Error("query string must not be logged")
	}
	if lines[1]["level"] != "DEBUG" || lines[1]["path"] != "/healthz" {
		t.Errorf("probe log = %v, want DEBUG level for /healthz", lines[1])
	}
}

func TestCrossOriginProtection(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	h := s.Handler()

	rec := do(t, h, "POST", "/api/v1/version", http.Header{"Sec-Fetch-Site": {"cross-site"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != contentTypeProblem {
		t.Errorf("Content-Type = %q, want %q", ct, contentTypeProblem)
	}
	// Same-origin unsafe requests pass the CSRF check (and then hit the 405).
	if rec := do(t, h, "POST", "/api/v1/version", http.Header{"Sec-Fetch-Site": {"same-origin"}}); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("same-origin POST status = %d, want 405", rec.Code)
	}
	// Safe methods are never blocked.
	if rec := do(t, h, "GET", "/api/v1/version", http.Header{"Sec-Fetch-Site": {"cross-site"}}); rec.Code != http.StatusOK {
		t.Errorf("cross-site GET status = %d, want 200", rec.Code)
	}
}

// codeWriter is a minimal ResponseWriter that records every WriteHeader call.
type codeWriter struct {
	header http.Header
	codes  []int
	body   bytes.Buffer
}

func (w *codeWriter) Header() http.Header         { return w.header }
func (w *codeWriter) WriteHeader(code int)        { w.codes = append(w.codes, code) }
func (w *codeWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

func TestResponseRecorder(t *testing.T) {
	t.Parallel()

	t.Run("informational then final status", func(t *testing.T) {
		t.Parallel()
		inner := &codeWriter{header: http.Header{}}
		rec := &responseRecorder{ResponseWriter: inner, status: http.StatusOK}
		rec.WriteHeader(http.StatusEarlyHints) // 1xx: not the final status
		rec.WriteHeader(http.StatusCreated)
		rec.WriteHeader(http.StatusTeapot) // superfluous: ignored for logging
		n, err := rec.Write([]byte("hello"))
		if err != nil || n != 5 {
			t.Fatalf("Write() = %d, %v", n, err)
		}
		if rec.status != http.StatusCreated || rec.bytes != 5 {
			t.Errorf("recorded status=%d bytes=%d, want 201/5", rec.status, rec.bytes)
		}
		if rec.Unwrap() != inner {
			t.Error("Unwrap() did not return the wrapped writer")
		}
	})

	t.Run("implicit 200 and flush passthrough", func(t *testing.T) {
		t.Parallel()
		inner := httptest.NewRecorder()
		rec := &responseRecorder{ResponseWriter: inner, status: http.StatusOK}
		if _, err := rec.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if !rec.wroteHeader || rec.status != http.StatusOK || inner.Code != http.StatusOK {
			t.Errorf("implicit WriteHeader not recorded: %+v", rec)
		}
		if err := http.NewResponseController(rec).Flush(); err != nil {
			t.Errorf("Flush via ResponseController: %v", err)
		}
		if !inner.Flushed {
			t.Error("Flush did not reach the underlying writer")
		}
	})
}

func TestStatusCaptureDefaultsTo200(t *testing.T) {
	t.Parallel()

	c := &statusCapture{header: http.Header{}}
	if _, err := c.Write([]byte("x")); err != nil || c.status != http.StatusOK {
		t.Errorf("status = %d, err = %v; want 200", c.status, err)
	}
}

func TestContentTypeFor(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"a.JS":         "text/javascript; charset=utf-8",
		"a.woff2":      "font/woff2",
		"a.js.map":     "application/json",
		"a.pdf":        "application/pdf", // from the stdlib mime table
		"a.nope":       "application/octet-stream",
		"no-extension": "application/octet-stream",
	}
	for name, want := range tests {
		if got := contentTypeFor(name); got != want {
			t.Errorf("contentTypeFor(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestHashedAssetPattern(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"assets/index-j5bd2x86.js":       true,
		"assets/index-j5bd2x86.js.map":   true,
		"assets/chunks/a-b-ABCDEFGH.css": true,
		"assets/logo.svg":                false,
		"assets/index-short.js":          false,
		"index-j5bd2x86.js":              false, // outside assets/
		"index.html":                     false,
	}
	for name, want := range tests {
		if got := hashedAsset.MatchString(name); got != want {
			t.Errorf("hashedAsset(%q) = %v, want %v", name, got, want)
		}
	}
}

// startServer runs s.Serve on a random loopback port and returns its base URL.
func startServer(t *testing.T, s *Server) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	base := "http://" + ln.Addr().String()
	waitFor(t, base+"/readyz", http.StatusOK)
	return base, cancel, done
}

func waitFor(t *testing.T, url string, status int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if res.StatusCode == status {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never returned %d", url, status)
}

func TestServeLifecycle(t *testing.T) {
	t.Parallel()

	s, logs := newTestServer(t, Options{Static: testFS()})
	base, cancel, done := startServer(t, s)

	res, err := http.Get(base + "/api/v1/version")
	if err != nil {
		t.Fatalf("GET version: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("version status = %d", res.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() = %v, want nil after graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after cancel")
	}
	if s.ready.Load() {
		t.Error("server still reports ready after shutdown")
	}
	for _, want := range []string{"http server listening", "shutting down", "shutdown complete"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs missing %q", want)
		}
	}
}

func TestServeShutdownTimeout(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	s.cfg.ShutdownTimeout = 50 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	slow := s.http.Handler
	s.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(entered)
			<-release
			return
		}
		slow.ServeHTTP(w, r)
	})

	base, cancel, done := startServer(t, s)
	go func() {
		res, err := http.Get(base + "/slow")
		if err == nil {
			_ = res.Body.Close()
		}
	}()
	<-entered
	cancel()

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Serve() = %v, want deadline exceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after shutdown timeout")
	}
}

func TestServeListenerFailure(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // Serve must surface the accept error instead of hanging
	if err := s.Serve(t.Context(), ln); err == nil {
		t.Fatal("Serve() on closed listener = nil, want error")
	}
	if s.ready.Load() {
		t.Error("ready after failed Serve")
	}
}

func TestListenAndServe(t *testing.T) {
	t.Parallel()

	t.Run("invalid address", func(t *testing.T) {
		t.Parallel()
		s, err := New(config.Config{Addr: "256.0.0.1:99999"}, Options{Version: testVersion})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ListenAndServe(t.Context()); err == nil || !strings.Contains(err.Error(), "listen on") {
			t.Fatalf("ListenAndServe() = %v, want listen error", err)
		}
	})

	t.Run("serves until cancelled", func(t *testing.T) {
		t.Parallel()
		s, err := New(config.Config{Addr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Options{Version: testVersion})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- s.ListenAndServe(ctx) }()
		deadline := time.Now().Add(5 * time.Second)
		for !s.ready.Load() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("ListenAndServe() = %v", err)
		}
	})
}

func TestServerTimeoutsConfigured(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, Options{})
	hs := s.http
	if hs.ReadHeaderTimeout <= 0 || hs.ReadTimeout <= 0 || hs.WriteTimeout <= 0 || hs.IdleTimeout <= 0 {
		t.Errorf("all timeouts must be set: %+v", hs)
	}
	if hs.MaxHeaderBytes != maxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want %d", hs.MaxHeaderBytes, maxHeaderBytes)
	}
	if hs.ErrorLog == nil {
		t.Error("ErrorLog must route net/http errors to slog")
	}
}
