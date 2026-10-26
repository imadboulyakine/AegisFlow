package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/version"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestRunFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "help", args: []string{"-h"}, wantCode: exitOK, wantStderr: "-healthcheck"},
		{name: "unknown flag", args: []string{"-nope"}, wantCode: exitUsage, wantStderr: "flag provided but not defined"},
		{name: "positional args", args: []string{"serve"}, wantCode: exitUsage, wantStderr: "unexpected arguments"},
		{name: "version", args: []string{"-version"}, wantCode: exitOK, wantStdout: `"goVersion"`},
		{name: "invalid config", env: map[string]string{"AEGISFLOW_LOG_LEVEL": "loud"}, wantCode: exitError, wantStderr: "invalid configuration"},
		{name: "invalid config healthcheck", args: []string{"-healthcheck"}, env: map[string]string{"AEGISFLOW_ADDR": "nope"}, wantCode: exitError, wantStderr: "AEGISFLOW_ADDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := run(t.Context(), tt.args, envMap(tt.env), &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestVersionOutputIsJSON(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if code := run(t.Context(), []string{"-version"}, envMap(nil), &stdout, &bytes.Buffer{}); code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	var info version.Info
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatalf("-version output is not JSON: %v\n%s", err, stdout.String())
	}
	if info != version.Get() {
		t.Errorf("-version = %+v, want %+v", info, version.Get())
	}
}

func TestHealthcheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		handler  http.HandlerFunc
		wantCode int
	}{
		{"healthy", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}, exitOK},
		{"unhealthy", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}, exitError},
		{"redirect is not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/", http.StatusFound)
		}, exitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(tt.handler)
			defer ts.Close()
			var stderr bytes.Buffer
			env := map[string]string{"AEGISFLOW_ADDR": ts.Listener.Addr().String()}
			if code := run(t.Context(), []string{"-healthcheck"}, envMap(env), &bytes.Buffer{}, &stderr); code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
		})
	}

	t.Run("nothing listening", func(t *testing.T) {
		t.Parallel()
		addr := freeAddr(t)
		var stderr bytes.Buffer
		if code := run(t.Context(), []string{"-healthcheck"}, envMap(map[string]string{"AEGISFLOW_ADDR": addr}), &bytes.Buffer{}, &stderr); code != exitError {
			t.Fatalf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(stderr.String(), "healthcheck:") {
			t.Errorf("stderr = %q, want healthcheck error", stderr.String())
		}
	})

	t.Run("malformed url", func(t *testing.T) {
		t.Parallel()
		if code := probe(t.Context(), "http://[::1", &bytes.Buffer{}); code != exitError {
			t.Fatalf("exit code = %d, want %d", code, exitError)
		}
	})
}

// TestRunServesAndShutsDown starts the real server, probes it with -healthcheck and
// checks that cancelling the context (as SIGTERM would) shuts it down cleanly.
func TestRunServesAndShutsDown(t *testing.T) {
	t.Parallel()

	addr := freeAddr(t)
	env := envMap(map[string]string{"AEGISFLOW_ADDR": addr, "AEGISFLOW_SHUTDOWN_TIMEOUT": "2s"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var logs syncWriter
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, env, &logs, &logs) }()

	deadline := time.Now().Add(10 * time.Second)
	for run(t.Context(), []string{"-healthcheck"}, env, &bytes.Buffer{}, &bytes.Buffer{}) != exitOK {
		if time.Now().After(deadline) {
			t.Fatalf("server never became healthy; logs:\n%s", logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("run() = %d after shutdown, want 0; logs:\n%s", code, logs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not return after cancel")
	}
	for _, want := range []string{`"msg":"starting aegisflow"`, `"service":"aegisflow"`, `"msg":"shutdown complete"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs missing %s", want)
		}
	}
}

func TestRunListenError(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var logs bytes.Buffer
	env := envMap(map[string]string{"AEGISFLOW_ADDR": ln.Addr().String()})
	if code := run(t.Context(), nil, env, &logs, &logs); code != exitError {
		t.Fatalf("run() on busy port = %d, want %d", code, exitError)
	}
	if !strings.Contains(logs.String(), "server stopped with error") {
		t.Errorf("logs = %s, want listen failure", logs.String())
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// syncWriter is a goroutine-safe buffer for capturing the server's logs.
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
