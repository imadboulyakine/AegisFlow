package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/config"
	"github.com/imadboulyakine/aegisflow/internal/ingest/ingesttest"
)

func TestRunStartsWithoutPhase2Settings(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	d, err := setup(t.Context(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if d.opts.Ingester != nil || d.opts.Verifier != nil || d.opts.Findings != nil || d.opts.Ready != nil {
		t.Fatalf("dependencies built without configuration: %+v", d.opts)
	}
	d.start(t.Context()) // no refresher: no-op
}

func TestSetupFailures(t *testing.T) {
	t.Parallel()
	unreachable := "postgres://aegisflow@127.0.0.1:1/aegisflow?sslmode=disable&connect_timeout=2"
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name: "refused audience fails before any I/O",
			env: map[string]string{
				config.EnvDatabaseURL: unreachable, config.EnvOIDCAudience: "api://AzureADTokenExchange", config.EnvOIDCOwnerIDs: "1",
			},
			wantErr: "oidc",
		},
		{name: "unreachable database", env: map[string]string{config.EnvDatabaseURL: unreachable}, wantErr: "database"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			if code := run(t.Context(), nil, envMap(tt.env), &logs, &logs); code != exitError {
				t.Fatalf("run() = %d, want %d", code, exitError)
			}
			if !strings.Contains(logs.String(), "startup failed") || !strings.Contains(logs.String(), tt.wantErr) {
				t.Errorf("logs = %s", logs.String())
			}
			if strings.Contains(logs.String(), "127.0.0.1:1/aegisflow") && strings.Contains(logs.String(), "password") {
				t.Error("database URL leaked")
			}
		})
	}
}

func TestSetupOIDCWithoutDatabase(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(envMap(map[string]string{config.EnvOIDCAudience: "aegisflow", config.EnvOIDCOwnerIDs: "1"}))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	d, err := setup(t.Context(), cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if d.opts.Ingester != nil || !strings.Contains(logs.String(), "evidence ingestion disabled") {
		t.Fatalf("opts = %+v logs = %s", d.opts, logs.String())
	}
}

// TestRunWithDatabaseAndOIDC starts the real binary entry point with PostgreSQL, OIDC and a local
// intel feed server, checks readiness and that ingestion is enabled, then shuts down.
func TestRunWithDatabaseAndOIDC(t *testing.T) {
	t.Parallel()
	dbURL := ingesttest.DatabaseURL(t)
	iss := ingesttest.NewIssuer(t)
	kev, err := os.ReadFile(filepath.Join("..", "..", "internal", "intel", "testdata", "kev_trimmed.json"))
	if err != nil {
		t.Fatal(err)
	}
	feeds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kev.json" {
			_, _ = w.Write(kev)
			return
		}
		http.NotFound(w, r) // not retried by the intel client
	}))
	t.Cleanup(feeds.Close)

	addr := freeAddr(t)
	env := envMap(map[string]string{
		"AEGISFLOW_ADDR": addr, "AEGISFLOW_SHUTDOWN_TIMEOUT": "2s",
		config.EnvDatabaseURL: dbURL, config.EnvOIDCAudience: "aegisflow-test", config.EnvOIDCIssuer: iss.URL,
		config.EnvOIDCRepositoryIDs: "101", config.EnvIntelKEVURL: feeds.URL + "/kev.json",
		config.EnvIntelEPSSURL: feeds.URL + "/epss.csv", config.EnvIntelRefreshInterval: "1h",
		config.EnvDefaultExposure: "internal", config.EnvDevReadOnlyAPI: "true",
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var logs syncWriter
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, env, &logs, &logs) }()

	base := "http://" + addr
	deadline := time.Now().Add(20 * time.Second)
	for {
		res, err := send(t, http.MethodGet, base+"/readyz", "")
		if err == nil {
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK && strings.Contains(string(body), `"database":"ok"`) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never became ready; logs:\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Ingestion is enabled: without a token the OIDC middleware answers 401 (not 503).
	res, err := send(t, http.MethodPost, base+"/api/v1/ingest", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ingest without token = %d", res.StatusCode)
	}
	res, err = send(t, http.MethodGet, base+"/api/v1/findings", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("findings = %d", res.StatusCode)
	}
	// Wait for the first intel refresh (KEV succeeds, EPSS fails and is logged).
	for !strings.Contains(logs.String(), `"feed":"epss"`) {
		if time.Now().After(deadline) {
			t.Fatalf("no intel refresh logged:\n%s", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("run() = %d; logs:\n%s", code, logs.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return after cancel")
	}
	out := logs.String()
	for _, want := range []string{`"msg":"database ready"`, `"ingest_enabled":true`, `"msg":"intel feed refreshed"`, `"feed":"kev"`, `"msg":"shutdown complete"`} {
		if !strings.Contains(out, want) {
			t.Errorf("logs missing %s", want)
		}
	}
	if pw := passwordOf(dbURL); pw != "" && strings.Contains(out, pw) {
		t.Error("database password leaked into logs")
	}
}

func send(t *testing.T, method, url, body string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// No keep-alive: a pooled or speculatively dialled connection would delay graceful shutdown.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	return client.Do(req)
}

func passwordOf(raw string) string {
	i := strings.Index(raw, "://")
	at := strings.Index(raw, "@")
	if i < 0 || at < 0 {
		return ""
	}
	userinfo := raw[i+3 : at]
	if _, pw, ok := strings.Cut(userinfo, ":"); ok {
		return pw
	}
	return ""
}
