package ghoidc

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// claimsEcho is the protected handler: it reports the repository ID it sees in the context.
var claimsEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	c, ok := ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no claims", http.StatusTeapot)
		return
	}
	_, _ = w.Write([]byte(c.RepositoryID))
})

func TestMiddleware(t *testing.T) {
	t.Parallel()
	valid := func(g gen) string { return mint(g.t, testKey(g.t, 0), nil, nil) }
	tests := []struct {
		name       string
		cfg        func(*Config)
		jwksDown   bool
		headers    func(gen) []string // Authorization values
		wantStatus int
		wantAuthn  string // WWW-Authenticate
		wantRetry  bool
		wantReason string
	}{
		{name: "valid token", headers: func(g gen) []string { return []string{"Bearer " + valid(g)} }, wantStatus: http.StatusOK},
		{name: "lowercase scheme", headers: func(g gen) []string { return []string{"bearer " + valid(g)} }, wantStatus: http.StatusOK},
		{name: "extra spaces before token", headers: func(g gen) []string { return []string{"Bearer   " + valid(g)} }, wantStatus: http.StatusOK},
		{name: "no header", headers: func(gen) []string { return nil },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow"`, wantReason: "missing_token"},
		{name: "basic scheme", headers: func(gen) []string { return []string{"Basic dXNlcjpwYXNz"} },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow"`, wantReason: "missing_token"},
		{name: "scheme only", headers: func(gen) []string { return []string{"Bearer"} },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow"`, wantReason: "missing_token"},
		{name: "empty token", headers: func(gen) []string { return []string{"Bearer   "} },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow"`, wantReason: "missing_token"},
		{name: "token with inner space", headers: func(gen) []string { return []string{"Bearer a b"} },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow"`, wantReason: "missing_token"},
		{name: "two authorization headers", headers: func(g gen) []string { return []string{"Bearer " + valid(g), "Bearer " + valid(g)} },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow"`, wantReason: "missing_token"},
		{name: "garbage token", headers: func(gen) []string { return []string{"Bearer not-a-jwt"} },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow", error="invalid_token"`, wantReason: "malformed"},
		{name: "alg none", headers: func(g gen) []string {
			return []string{"Bearer " + mint(g.t, testKey(g.t, 0), func(h map[string]any) { h["alg"] = "none" }, nil)}
		}, wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow", error="invalid_token"`, wantReason: "unsupported_alg"},
		{name: "bad signature", headers: func(g gen) []string { return []string{"Bearer " + mint(g.t, testKey(g.t, 1), nil, nil)} },
			wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow", error="invalid_token"`, wantReason: "bad_signature"},
		{name: "expired", headers: func(g gen) []string {
			return []string{"Bearer " + mint(g.t, testKey(g.t, 0), nil, func(c map[string]any) {
				c["iat"] = testNow.Add(-20 * time.Minute).Unix()
				c["exp"] = testNow.Add(-10 * time.Minute).Unix()
			})}
		}, wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow", error="invalid_token"`, wantReason: "expired"},
		{name: "wrong audience", headers: func(g gen) []string {
			return []string{"Bearer " + mint(g.t, testKey(g.t, 0), nil, func(c map[string]any) { c["aud"] = "other" })}
		}, wantStatus: http.StatusUnauthorized, wantAuthn: `Bearer realm="aegisflow", error="invalid_token"`, wantReason: "bad_audience"},
		{name: "repository not allowed", headers: func(g gen) []string {
			return []string{"Bearer " + mint(g.t, testKey(g.t, 0), nil, func(c map[string]any) { c["repository_id"] = "75" })}
		}, wantStatus: http.StatusForbidden, wantReason: "repository_not_allowed"},
		{name: "ref not allowed", cfg: func(c *Config) { c.AllowedRefs = []string{"refs/heads/release"} },
			headers: func(g gen) []string { return []string{"Bearer " + valid(g)} }, wantStatus: http.StatusForbidden, wantReason: "ref_not_allowed"},
		{name: "jwks unavailable", jwksDown: true, headers: func(g gen) []string { return []string{"Bearer " + valid(g)} },
			wantStatus: http.StatusServiceUnavailable, wantRetry: true, wantReason: "jwks_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t, tt.cfg)
			if tt.jwksDown {
				env.srv.set(nil, http.StatusInternalServerError)
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			h := Middleware(env.v, WithLogger(logger))(claimsEcho)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
			headers := tt.headers(gen{t})
			for _, v := range headers {
				req.Header.Add("Authorization", v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.wantAuthn {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.wantAuthn)
			}
			if got := rec.Header().Get("Retry-After"); (got != "") != tt.wantRetry {
				t.Errorf("Retry-After = %q, want present=%v", got, tt.wantRetry)
			}
			if tt.wantStatus == http.StatusOK {
				if rec.Body.String() != "74" {
					t.Errorf("handler saw repository_id %q", rec.Body)
				}
				if !strings.Contains(logs.String(), `"msg":"oidc token accepted"`) {
					t.Errorf("acceptance not logged: %s", logs.String())
				}
				return
			}
			assertProblem(t, rec, tt.wantStatus)
			// Clients get a generic detail; the precise reason goes to the log only.
			for _, leak := range []string{"kid", "ghoidc", "repository_id", "74", "75", "RS256", "jwks"} {
				if strings.Contains(rec.Body.String(), leak) {
					t.Errorf("problem body leaks %q: %s", leak, rec.Body)
				}
			}
			if !strings.Contains(logs.String(), `"reason":"`+tt.wantReason+`"`) {
				t.Errorf("log lacks reason %q: %s", tt.wantReason, logs.String())
			}
			for _, v := range headers {
				if tok, ok := strings.CutPrefix(v, "Bearer "); ok && len(tok) > 20 && strings.Contains(logs.String(), tok) {
					t.Error("token written to the log")
				}
			}
		})
	}
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != contentTypeProblem {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var p problem
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("problem body: %v", err)
	}
	if p.Type != "about:blank" || p.Status != status || p.Title != http.StatusText(status) || p.Detail == "" ||
		p.Instance != "/api/v1/ingest" {
		t.Errorf("problem = %+v", p)
	}
}

func TestMiddlewareNilVerifierFailsClosed(t *testing.T) {
	t.Parallel()
	h := Middleware(nil)(claimsEcho)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingest", http.NoBody)
	req.Header.Set("Authorization", "Bearer x.y.z")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestMiddlewareCustomErrorWriter(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	var gotStatus int
	var gotDetail string
	custom := func(w http.ResponseWriter, _ *http.Request, status int, detail string) {
		gotStatus, gotDetail = status, detail
		w.WriteHeader(status)
	}
	h := Middleware(env.v, WithErrorWriter(custom), WithErrorWriter(nil))(claimsEcho)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/gate", http.NoBody))
	if gotStatus != http.StatusUnauthorized || gotDetail == "" || rec.Code != http.StatusUnauthorized {
		t.Fatalf("custom writer got status=%d detail=%q, response %d", gotStatus, gotDetail, rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate must be set before the custom writer runs")
	}
}

func TestClaimsContext(t *testing.T) {
	t.Parallel()
	if _, ok := ClaimsFromContext(context.Background()); ok {
		t.Error("empty context reported claims")
	}
	if _, ok := ClaimsFromContext(ContextWithClaims(context.Background(), nil)); ok {
		t.Error("nil claims reported as present")
	}
	want := &Claims{RepositoryID: "74"}
	got, ok := ClaimsFromContext(ContextWithClaims(context.Background(), want))
	if !ok || got != want {
		t.Errorf("ClaimsFromContext = %v, %v", got, ok)
	}
}

func TestClassifyAndReasons(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err    error
		status int
		reason string
	}{
		{ErrMalformed, 401, "malformed"},
		{ErrMissingClaim, 401, "missing_claim"},
		{ErrUnsupportedAlg, 401, "unsupported_alg"},
		{ErrUnknownKey, 401, "unknown_key"},
		{ErrSignature, 401, "bad_signature"},
		{ErrIssuer, 401, "bad_issuer"},
		{ErrAudience, 401, "bad_audience"},
		{ErrExpired, 401, "expired"},
		{ErrNotYetValid, 401, "not_yet_valid"},
		{ErrJWKSUnavailable, 503, "jwks_unavailable"},
		{ErrRepositoryNotAllowed, 403, "repository_not_allowed"},
		{ErrRefNotAllowed, 403, "ref_not_allowed"},
		{ErrEnvironmentNotAllowed, 403, "environment_not_allowed"},
		{ErrCommitMismatch, 403, "forbidden"},
		{context.Canceled, 401, "invalid_token"},
	}
	for _, tt := range tests {
		if status, detail := classify(tt.err); status != tt.status || detail == "" {
			t.Errorf("classify(%v) = %d, %q; want %d", tt.err, status, detail, tt.status)
		}
		if got := reasonOf(tt.err); got != tt.reason {
			t.Errorf("reasonOf(%v) = %q, want %q", tt.err, got, tt.reason)
		}
	}
}
