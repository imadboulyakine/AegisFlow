package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadPhase2Defaults(t *testing.T) {
	t.Parallel()
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Enabled() || cfg.IngestEnabled() || cfg.DevReadOnlyAPI {
		t.Errorf("defaults enable ingestion or the read API: %+v", cfg)
	}
	if cfg.DefaultExposure != "unknown" || cfg.Intel.RefreshInterval != DefaultIntelRefreshInterval ||
		cfg.Intel.KEVURL != "" || cfg.Intel.EPSSURL != "" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadOIDC(t *testing.T) {
	t.Parallel()
	db := "postgres://aegisflow@127.0.0.1:5432/aegisflow?sslmode=disable"
	tests := []struct {
		name       string
		env        map[string]string
		wantErr    string
		wantIngest bool
		check      func(t *testing.T, c Config)
	}{
		{
			name: "full configuration",
			env: map[string]string{
				EnvDatabaseURL: db, EnvOIDCAudience: "aegisflow-ingest",
				EnvOIDCRepositoryIDs: " 123, 456 ,123", EnvOIDCOwnerIDs: "789",
				EnvOIDCAllowedRefs: "refs/heads/main,refs/tags/v1.0.0", EnvOIDCAllowedEnvironments: "prod",
				EnvOIDCIssuer: "https://token.actions.githubusercontent.com/octo-enterprise",
			},
			wantIngest: true,
			check: func(t *testing.T, c Config) {
				t.Helper()
				if !slices.Equal(c.OIDC.AllowedRepositoryIDs, []int64{123, 456}) ||
					!slices.Equal(c.OIDC.AllowedOwnerIDs, []int64{789}) ||
					!slices.Equal(c.OIDC.AllowedRefs, []string{"refs/heads/main", "refs/tags/v1.0.0"}) ||
					!slices.Equal(c.OIDC.AllowedEnvironments, []string{"prod"}) ||
					c.OIDC.Issuer != "https://token.actions.githubusercontent.com/octo-enterprise" {
					t.Errorf("OIDC = %+v", c.OIDC)
				}
			},
		},
		{name: "oidc without database", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "1"}},
		{name: "owner list only", env: map[string]string{EnvDatabaseURL: db, EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "1"}, wantIngest: true},
		{name: "audience without lists", env: map[string]string{EnvOIDCAudience: "a"}, wantErr: "numeric GitHub IDs"},
		{name: "lists without audience", env: map[string]string{EnvOIDCRepositoryIDs: "1"}, wantErr: "without " + EnvOIDCAudience},
		{name: "issuer without audience", env: map[string]string{EnvOIDCIssuer: "https://x.example"}, wantErr: "without"},
		{name: "audience with space", env: map[string]string{EnvOIDCAudience: "a b", EnvOIDCOwnerIDs: "1"}, wantErr: "without spaces"},
		{name: "audience too long", env: map[string]string{EnvOIDCAudience: strings.Repeat("a", 257), EnvOIDCOwnerIDs: "1"}, wantErr: "at most"},
		{name: "name instead of id", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCRepositoryIDs: "octo/repo"}, wantErr: "positive decimal ID"},
		{name: "zero id", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "0"}, wantErr: "positive decimal ID"},
		{name: "leading zero id", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "012"}, wantErr: "positive decimal ID"},
		{name: "negative id", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "-5"}, wantErr: "positive decimal ID"},
		{name: "empty entry", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "1,,2"}, wantErr: "empty list entry"},
		{name: "too many entries", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: strings.Repeat("1,", 64) + "1"}, wantErr: "more than"},
		{name: "control char in ref", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "1", EnvOIDCAllowedRefs: "refs/heads/\x01"}, wantErr: "control"},
		{name: "http issuer", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "1", EnvOIDCIssuer: "http://issuer.example"}, wantErr: "loopback"},
		{name: "loopback http issuer", env: map[string]string{EnvOIDCAudience: "a", EnvOIDCOwnerIDs: "1", EnvOIDCIssuer: "http://127.0.0.1:9999"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Load(env(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.IngestEnabled() != tt.wantIngest {
				t.Errorf("IngestEnabled() = %v, want %v", cfg.IngestEnabled(), tt.wantIngest)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestLoadIntelExposureDevAPI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
		check   func(t *testing.T, c Config)
	}{
		{name: "feeds and interval", env: map[string]string{
			EnvIntelKEVURL:          "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
			EnvIntelEPSSURL:         "http://127.0.0.1:8081/epss.csv.gz",
			EnvIntelRefreshInterval: "6h",
		}, check: func(t *testing.T, c Config) {
			t.Helper()
			if c.Intel.RefreshInterval != 6*time.Hour || !strings.HasPrefix(c.Intel.KEVURL, "https://raw.") ||
				c.Intel.EPSSURL != "http://127.0.0.1:8081/epss.csv.gz" {
				t.Errorf("Intel = %+v", c.Intel)
			}
		}},
		{name: "refresher disabled", env: map[string]string{EnvIntelRefreshInterval: "0"}, check: func(t *testing.T, c Config) {
			t.Helper()
			if c.Intel.RefreshInterval != 0 {
				t.Errorf("RefreshInterval = %s", c.Intel.RefreshInterval)
			}
		}},
		{name: "interval too short", env: map[string]string{EnvIntelRefreshInterval: "10s"}, wantErr: "out of range"},
		{name: "interval too long", env: map[string]string{EnvIntelRefreshInterval: "200h"}, wantErr: "out of range"},
		{name: "interval garbage", env: map[string]string{EnvIntelRefreshInterval: "daily"}, wantErr: "invalid duration"},
		{name: "kev plain http", env: map[string]string{EnvIntelKEVURL: "http://feeds.example/kev.json"}, wantErr: "loopback"},
		{name: "kev with credentials", env: map[string]string{EnvIntelKEVURL: "https://u:p@feeds.example/kev.json"}, wantErr: "credentials"},
		{name: "kev ftp", env: map[string]string{EnvIntelKEVURL: "ftp://feeds.example/kev.json"}, wantErr: "scheme"},
		{name: "kev relative", env: map[string]string{EnvIntelKEVURL: "/kev.json"}, wantErr: "absolute"},
		{name: "kev with space", env: map[string]string{EnvIntelKEVURL: "https://feeds.example/a b"}, wantErr: "without spaces"},
		{name: "exposure", env: map[string]string{EnvDefaultExposure: " Internet "}, check: func(t *testing.T, c Config) {
			t.Helper()
			if c.DefaultExposure != "internet" {
				t.Errorf("DefaultExposure = %q", c.DefaultExposure)
			}
		}},
		{name: "bad exposure", env: map[string]string{EnvDefaultExposure: "public"}, wantErr: "unknown exposure"},
		{name: "dev api", env: map[string]string{EnvDevReadOnlyAPI: "true"}, check: func(t *testing.T, c Config) {
			t.Helper()
			if !c.DevReadOnlyAPI {
				t.Error("DevReadOnlyAPI = false")
			}
		}},
		{name: "dev api garbage", env: map[string]string{EnvDevReadOnlyAPI: "yes please"}, wantErr: "true or false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Load(env(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			tt.check(t, cfg)
		})
	}
}

func TestTruncateValue(t *testing.T) {
	t.Parallel()
	if got := truncateValue(strings.Repeat("x", 100)); len(got) != 64+len("…") {
		t.Errorf("truncateValue = %q", got)
	}
}
