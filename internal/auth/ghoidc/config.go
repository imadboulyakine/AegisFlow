package ghoidc

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults and hard limits.
const (
	// DefaultIssuer is the `iss` of GitHub.com Actions OIDC tokens.
	DefaultIssuer = "https://token.actions.githubusercontent.com"
	// DefaultClockSkew tolerates small clock differences when checking exp, nbf and iat.
	DefaultClockSkew = 60 * time.Second
	// MaxClockSkew bounds Config.ClockSkew; a larger value would silently extend token lifetime.
	MaxClockSkew = 5 * time.Minute
	// DefaultJWKSCacheTTL is how long a fetched key set is used before it is refreshed.
	DefaultJWKSCacheTTL = time.Hour
	// DefaultJWKSMinRefreshInterval is the minimum delay between two key set fetches, whatever
	// triggers them (unknown kid, TTL expiry, failed fetch). It caps the fetch rate an attacker
	// can cause by presenting tokens with random `kid` values.
	DefaultJWKSMinRefreshInterval = 30 * time.Second
	// MaxTokenBytes is the largest token Verify accepts (GitHub tokens are about 1-2 KiB).
	MaxTokenBytes = 16 << 10

	jwksPathSuffix     = "/.well-known/jwks"
	defaultHTTPTimeout = 10 * time.Second
)

// Config configures a Verifier. Audience and at least one of AllowedRepositoryIDs /
// AllowedOwnerIDs are required; everything else has a safe default.
type Config struct {
	// Issuer is the exact expected `iss` (default DefaultIssuer). GitHub Enterprise Cloud
	// customised issuers (https://token.actions.githubusercontent.com/<slug>) also work.
	Issuer string
	// Audience is AegisFlow's custom audience, requested in CI with
	// `core.getIDToken('<audience>')`. Required. GitHub's default audience
	// (https://github.com/<owner>) and Azure's token-exchange audience are refused so that tokens
	// minted for other relying parties cannot be replayed against AegisFlow.
	Audience string
	// JWKSURL is where signing keys are fetched (default Issuer + "/.well-known/jwks").
	JWKSURL string

	// AllowedRepositoryIDs lists accepted `repository_id` values. When non-empty, the token's
	// repository must be one of them.
	AllowedRepositoryIDs []int64
	// AllowedOwnerIDs lists accepted `repository_owner_id` values (user or organisation). When
	// non-empty, the token's owner must be one of them. When both lists are set, both must match.
	AllowedOwnerIDs []int64
	// AllowedRefs optionally restricts `ref` to exact values such as "refs/heads/main".
	AllowedRefs []string
	// AllowedEnvironments optionally restricts `environment` to exact values; a token without an
	// environment is then refused.
	AllowedEnvironments []string

	// ClockSkew tolerates clock drift for exp/nbf/iat (default DefaultClockSkew, at most MaxClockSkew).
	ClockSkew time.Duration
	// HTTPClient fetches the JWKS. Default: a client with a 10 s timeout that does not follow
	// redirects.
	HTTPClient *http.Client
	// JWKSCacheTTL is the key set lifetime (default DefaultJWKSCacheTTL).
	JWKSCacheTTL time.Duration
	// JWKSMinRefreshInterval is the minimum delay between key set fetches
	// (default DefaultJWKSMinRefreshInterval).
	JWKSMinRefreshInterval time.Duration
}

// reservedAudiences are audiences of other relying parties; accepting them would let a token
// minted for Azure (or GitHub's default audience) be replayed against AegisFlow.
var reservedAudiences = []string{"api://AzureADTokenExchange"}

// withDefaults returns a copy of c with defaults applied. Slices are copied by the Verifier.
func (c Config) withDefaults() Config {
	if c.Issuer == "" {
		c.Issuer = DefaultIssuer
	}
	if c.JWKSURL == "" {
		c.JWKSURL = c.Issuer + jwksPathSuffix
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = DefaultClockSkew
	}
	if c.JWKSCacheTTL == 0 {
		c.JWKSCacheTTL = DefaultJWKSCacheTTL
	}
	if c.JWKSMinRefreshInterval == 0 {
		c.JWKSMinRefreshInterval = DefaultJWKSMinRefreshInterval
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			Timeout: defaultHTTPTimeout,
			// The JWKS is served directly by the issuer; refusing redirects keeps key material
			// from being sourced from anywhere but the configured URL.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return c
}

// validate checks a Config that already has defaults applied. All problems are reported.
func (c Config) validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if err := validateEndpoint(c.Issuer, false); err != nil {
		add("issuer: %w", err)
	}
	if err := validateEndpoint(c.JWKSURL, true); err != nil {
		add("jwks url: %w", err)
	}
	switch {
	case strings.TrimSpace(c.Audience) == "":
		add("audience is required")
	case c.Audience != strings.TrimSpace(c.Audience):
		add("audience must not have surrounding whitespace")
	case strings.HasPrefix(c.Audience, "https://github.com/"):
		add("audience %q is GitHub's default audience; configure a custom audience", c.Audience)
	default:
		for _, r := range reservedAudiences {
			if strings.EqualFold(c.Audience, r) {
				add("audience %q belongs to another relying party", c.Audience)
			}
		}
	}
	if len(c.AllowedRepositoryIDs) == 0 && len(c.AllowedOwnerIDs) == 0 {
		add("at least one of AllowedRepositoryIDs or AllowedOwnerIDs is required")
	}
	for _, id := range c.AllowedRepositoryIDs {
		if id <= 0 {
			add("repository id %d must be positive", id)
		}
	}
	for _, id := range c.AllowedOwnerIDs {
		if id <= 0 {
			add("owner id %d must be positive", id)
		}
	}
	for _, ref := range c.AllowedRefs {
		if !strings.HasPrefix(ref, "refs/") || len(ref) == len("refs/") || strings.ContainsAny(ref, " *?[") {
			add("ref %q must be a full ref such as refs/heads/main (no patterns)", ref)
		}
	}
	for _, env := range c.AllowedEnvironments {
		if strings.TrimSpace(env) == "" {
			add("environment names must not be empty")
		}
	}
	if c.ClockSkew < 0 || c.ClockSkew > MaxClockSkew {
		add("clock skew %s must be within [0, %s]", c.ClockSkew, MaxClockSkew)
	}
	if c.JWKSCacheTTL < 0 {
		add("jwks cache ttl %s must not be negative", c.JWKSCacheTTL)
	}
	if c.JWKSMinRefreshInterval < 0 {
		add("jwks min refresh interval %s must not be negative", c.JWKSMinRefreshInterval)
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrInvalidConfig, errors.Join(errs...))
}

// validateEndpoint accepts absolute https URLs, or http on a loopback host (local development
// and tests). The issuer must not carry a query or trailing slash because `iss` is compared
// byte for byte.
func validateEndpoint(raw string, allowQuery bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse %q: %w", raw, err)
	}
	switch {
	case u.Host == "" || u.Opaque != "":
		return fmt.Errorf("%q is not an absolute URL", raw)
	case u.User != nil:
		return fmt.Errorf("%q must not contain user info", raw)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return fmt.Errorf("%q must not contain a fragment", raw)
	case !allowQuery && (u.RawQuery != "" || strings.Contains(raw, "?")):
		return fmt.Errorf("%q must not contain a query", raw)
	case !allowQuery && strings.HasSuffix(raw, "/"):
		return fmt.Errorf("%q must not end with a slash", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%q must use https (http is only allowed for loopback hosts)", raw)
	default:
		return fmt.Errorf("%q must use https", raw)
	}
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
