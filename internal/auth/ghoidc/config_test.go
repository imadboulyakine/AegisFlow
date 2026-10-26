package ghoidc

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{Audience: testAudience, AllowedRepositoryIDs: []int64{testRepoID}}
}

func TestNewVerifierDefaults(t *testing.T) {
	t.Parallel()
	v, err := NewVerifier(validConfig())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v.issuer != DefaultIssuer || v.audience != testAudience || v.skew != DefaultClockSkew {
		t.Errorf("issuer=%q audience=%q skew=%s", v.issuer, v.audience, v.skew)
	}
	if want := DefaultIssuer + "/.well-known/jwks"; v.keys.url != want {
		t.Errorf("jwks url = %q, want %q", v.keys.url, want)
	}
	if v.keys.ttl != DefaultJWKSCacheTTL || v.keys.minInterval != DefaultJWKSMinRefreshInterval {
		t.Errorf("ttl=%s minInterval=%s", v.keys.ttl, v.keys.minInterval)
	}
	if v.keys.client == nil || v.keys.client.Timeout != defaultHTTPTimeout || v.keys.client.CheckRedirect == nil {
		t.Errorf("default client = %+v", v.keys.client)
	}
	if !errors.Is(v.keys.client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Error("default client must not follow redirects")
	}
}

func TestNewVerifierCustomIssuerDerivesJWKSURL(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Issuer = "https://token.actions.githubusercontent.com/avocado-corp"
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v.keys.url != cfg.Issuer+"/.well-known/jwks" {
		t.Errorf("jwks url = %q", v.keys.url)
	}
}

func TestNewVerifierRejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		edit    func(*Config)
		wantMsg string
	}{
		{name: "missing audience", edit: func(c *Config) { c.Audience = "" }, wantMsg: "audience is required"},
		{name: "blank audience", edit: func(c *Config) { c.Audience = "  " }, wantMsg: "audience is required"},
		{name: "audience with whitespace", edit: func(c *Config) { c.Audience = " aegisflow" }, wantMsg: "whitespace"},
		{name: "github default audience", edit: func(c *Config) { c.Audience = "https://github.com/octo-org" }, wantMsg: "default audience"},
		{name: "azure audience", edit: func(c *Config) { c.Audience = "api://AzureADTokenExchange" }, wantMsg: "another relying party"},
		{name: "no allow-list", edit: func(c *Config) { c.AllowedRepositoryIDs = nil }, wantMsg: "at least one"},
		{name: "zero repository id", edit: func(c *Config) { c.AllowedRepositoryIDs = []int64{0} }, wantMsg: "must be positive"},
		{name: "negative owner id", edit: func(c *Config) { c.AllowedOwnerIDs = []int64{-1} }, wantMsg: "must be positive"},
		{name: "short ref", edit: func(c *Config) { c.AllowedRefs = []string{"main"} }, wantMsg: "full ref"},
		{name: "ref pattern", edit: func(c *Config) { c.AllowedRefs = []string{"refs/tags/*"} }, wantMsg: "no patterns"},
		{name: "bare refs prefix", edit: func(c *Config) { c.AllowedRefs = []string{"refs/"} }, wantMsg: "full ref"},
		{name: "empty environment", edit: func(c *Config) { c.AllowedEnvironments = []string{""} }, wantMsg: "environment"},
		{name: "negative skew", edit: func(c *Config) { c.ClockSkew = -time.Second }, wantMsg: "clock skew"},
		{name: "huge skew", edit: func(c *Config) { c.ClockSkew = time.Hour }, wantMsg: "clock skew"},
		{name: "negative ttl", edit: func(c *Config) { c.JWKSCacheTTL = -time.Second }, wantMsg: "ttl"},
		{name: "negative refresh interval", edit: func(c *Config) { c.JWKSMinRefreshInterval = -time.Second }, wantMsg: "refresh interval"},
		{name: "http issuer", edit: func(c *Config) { c.Issuer = "http://token.actions.githubusercontent.com" }, wantMsg: "https"},
		{name: "issuer trailing slash", edit: func(c *Config) { c.Issuer = DefaultIssuer + "/" }, wantMsg: "slash"},
		{name: "issuer query", edit: func(c *Config) { c.Issuer = DefaultIssuer + "?x=1" }, wantMsg: "query"},
		{name: "issuer fragment", edit: func(c *Config) { c.Issuer = DefaultIssuer + "#x" }, wantMsg: "fragment"},
		{name: "issuer userinfo", edit: func(c *Config) { c.Issuer = "https://user@token.actions.githubusercontent.com" }, wantMsg: "user info"},
		{name: "relative issuer", edit: func(c *Config) { c.Issuer = "token.actions.githubusercontent.com" }, wantMsg: "absolute"},
		{name: "unparsable issuer", edit: func(c *Config) { c.Issuer = "https://bad host" }, wantMsg: "issuer"},
		{name: "ftp jwks", edit: func(c *Config) { c.JWKSURL = "ftp://example.com/jwks" }, wantMsg: "https"},
		{name: "http jwks on public host", edit: func(c *Config) { c.JWKSURL = "http://example.com/jwks" }, wantMsg: "loopback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			tt.edit(&cfg)
			v, err := NewVerifier(cfg)
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("NewVerifier error = %v, want ErrInvalidConfig containing %q", err, tt.wantMsg)
			}
			if v != nil {
				t.Error("verifier returned with error")
			}
		})
	}
}

func TestNewVerifierReportsAllProblems(t *testing.T) {
	t.Parallel()
	_, err := NewVerifier(Config{ClockSkew: -1})
	for _, want := range []string{"audience is required", "at least one", "clock skew"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v lacks %q", err, want)
		}
	}
}

func TestLoopbackHTTPAllowed(t *testing.T) {
	t.Parallel()
	for _, u := range []string{"http://127.0.0.1:8080/jwks", "http://localhost/jwks", "http://[::1]:9/jwks"} {
		cfg := validConfig()
		cfg.JWKSURL = u
		if _, err := NewVerifier(cfg); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}
