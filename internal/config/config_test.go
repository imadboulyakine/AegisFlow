package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr []string // substrings expected in the error
	}{
		{
			name: "defaults",
			env:  nil,
			want: Config{Addr: ":8080", LogLevel: slog.LevelInfo, ShutdownTimeout: 10 * time.Second},
		},
		{
			name: "all overrides",
			env: map[string]string{
				EnvAddr:            "127.0.0.1:9090",
				EnvLogLevel:        "DEBUG",
				EnvShutdownTimeout: "30s",
			},
			want: Config{Addr: "127.0.0.1:9090", LogLevel: slog.LevelDebug, ShutdownTimeout: 30 * time.Second},
		},
		{
			name: "whitespace is trimmed and empty means default",
			env:  map[string]string{EnvAddr: "  ", EnvLogLevel: " warn ", EnvShutdownTimeout: ""},
			want: Config{Addr: ":8080", LogLevel: slog.LevelWarn, ShutdownTimeout: 10 * time.Second},
		},
		{
			name: "ipv6 and localhost hosts",
			env:  map[string]string{EnvAddr: "[::1]:8081", EnvLogLevel: "error"},
			want: Config{Addr: "[::1]:8081", LogLevel: slog.LevelError, ShutdownTimeout: 10 * time.Second},
		},
		{
			name: "localhost is accepted",
			env:  map[string]string{EnvAddr: "localhost:8080", EnvLogLevel: "warning"},
			want: Config{Addr: "localhost:8080", LogLevel: slog.LevelWarn, ShutdownTimeout: 10 * time.Second},
		},
		{name: "missing port", env: map[string]string{EnvAddr: "8080"}, wantErr: []string{EnvAddr}},
		{name: "port out of range", env: map[string]string{EnvAddr: ":70000"}, wantErr: []string{"invalid port"}},
		{name: "non-numeric port", env: map[string]string{EnvAddr: ":http"}, wantErr: []string{"invalid port"}},
		{name: "hostname not allowed", env: map[string]string{EnvAddr: "example.com:80"}, wantErr: []string{"invalid host"}},
		{name: "bad log level", env: map[string]string{EnvLogLevel: "verbose"}, wantErr: []string{EnvLogLevel, "verbose"}},
		{name: "bad duration", env: map[string]string{EnvShutdownTimeout: "10"}, wantErr: []string{"invalid duration"}},
		{name: "zero duration", env: map[string]string{EnvShutdownTimeout: "0s"}, wantErr: []string{"out of range"}},
		{name: "negative duration", env: map[string]string{EnvShutdownTimeout: "-1s"}, wantErr: []string{"out of range"}},
		{name: "too long duration", env: map[string]string{EnvShutdownTimeout: "1h"}, wantErr: []string{"out of range"}},
		{
			name:    "errors are reported together",
			env:     map[string]string{EnvAddr: "nope", EnvLogLevel: "loud", EnvShutdownTimeout: "soon"},
			wantErr: []string{EnvAddr, EnvLogLevel, EnvShutdownTimeout},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Load(env(tt.env))
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("Load() error = nil, want error containing %q", tt.wantErr)
				}
				for _, s := range tt.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("Load() error = %q, want it to contain %q", err, s)
					}
				}
				if got != (Config{}) {
					t.Errorf("Load() returned non-zero config on error: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHealthcheckURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want string
	}{
		{":8080", "http://127.0.0.1:8080/healthz"},
		{"0.0.0.0:9000", "http://127.0.0.1:9000/healthz"},
		{"[::]:9000", "http://[::1]:9000/healthz"},
		{"localhost:8081", "http://127.0.0.1:8081/healthz"},
		{"10.1.2.3:8080", "http://10.1.2.3:8080/healthz"},
		{"[::1]:8080", "http://[::1]:8080/healthz"},
		{"garbage", "http://127.0.0.1:8080/healthz"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()
			if got := (Config{Addr: tt.addr}).HealthcheckURL(); got != tt.want {
				t.Errorf("HealthcheckURL(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
