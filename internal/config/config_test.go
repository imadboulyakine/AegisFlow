package config

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// randomSecret returns a throwaway credential generated at test time (no secret-looking literals
// in the repository).
func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestLoadDatabaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    string // expected Config.DatabaseURL ("" = disabled)
		wantErr string // substring of the error ("" = no error)
	}{
		{name: "unset means no database", value: "", want: ""},
		{name: "blank means no database", value: "   ", want: ""},
		{
			name:  "postgres scheme",
			value: "postgres://aegisflow@127.0.0.1:5432/aegisflow?sslmode=disable",
			want:  "postgres://aegisflow@127.0.0.1:5432/aegisflow?sslmode=disable",
		},
		{
			name:  "postgresql scheme, trimmed",
			value: " postgresql://db.internal/aegisflow?sslmode=verify-full ",
			want:  "postgresql://db.internal/aegisflow?sslmode=verify-full",
		},
		{
			name:  "unix socket via host parameter",
			value: "postgres:///aegisflow?host=/var/run/postgresql",
			want:  "postgres:///aegisflow?host=/var/run/postgresql",
		},
		{name: "keyword/value DSN rejected", value: "host=localhost dbname=x", wantErr: "spaces or control"},
		{name: "wrong scheme", value: "mysql://localhost/x", wantErr: "scheme must be"},
		{name: "no scheme", value: "localhost:5432/x", wantErr: "scheme must be"},
		{name: "missing host", value: "postgres:///aegisflow", wantErr: "missing host"},
		{name: "bad port", value: "postgres://localhost:99999/x", wantErr: "invalid port"},
		{name: "bad sslmode", value: "postgres://localhost/x?sslmode=sometimes", wantErr: "invalid sslmode"},
		{name: "control character", value: "postgres://localhost/x\x7f", wantErr: "control"},
		{name: "unparseable", value: "postgres://[::1/x", wantErr: "not a valid URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Load(env(map[string]string{EnvDatabaseURL: tt.value}))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), EnvDatabaseURL) {
					t.Fatalf("Load() error = %v, want it to mention %q and %s", err, tt.wantErr, EnvDatabaseURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if got.DatabaseURL != tt.want {
				t.Errorf("DatabaseURL = %q, want %q", got.DatabaseURL, tt.want)
			}
		})
	}
}

func TestDatabaseURLNeverLeaksPassword(t *testing.T) {
	t.Parallel()
	pw := randomSecret(t)

	// Invalid URLs: the error must not echo the value (url.Error would).
	for _, raw := range []string{
		"postgres://u:" + pw + "@[::1/x",
		"postgres://u:" + pw + "@localhost:0/x",
		"postgres://u:" + pw + "@localhost/x?sslmode=" + pw,
		"mysql://u:" + pw + "@localhost/x",
	} {
		_, err := Load(env(map[string]string{EnvDatabaseURL: raw}))
		if err == nil {
			t.Fatalf("Load() accepted an invalid URL")
		}
		if strings.Contains(err.Error(), pw) {
			t.Errorf("error leaks the password: %v", err)
		}
	}

	// Valid URL: RedactedDatabaseURL masks the password and keeps the rest.
	cfg, err := Load(env(map[string]string{EnvDatabaseURL: "postgres://aegisflow:" + pw + "@127.0.0.1:5432/aegisflow"}))
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	red := cfg.RedactedDatabaseURL()
	if strings.Contains(red, pw) || !strings.Contains(red, "127.0.0.1:5432/aegisflow") || !strings.Contains(red, "xxxxx") {
		t.Errorf("RedactedDatabaseURL() = %q", red)
	}
	if (Config{}).RedactedDatabaseURL() != "" {
		t.Error("RedactedDatabaseURL() of an unconfigured database should be empty")
	}
	if got := (Config{DatabaseURL: "postgres://[::1"}).RedactedDatabaseURL(); got != "(unparseable)" {
		t.Errorf("RedactedDatabaseURL() of garbage = %q", got)
	}
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
