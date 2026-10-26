// Package config loads AegisFlow runtime configuration from environment variables.
//
// Configuration is environment-only (12-factor) so the same image runs locally, in CI
// and on Azure Container Apps. Secrets must never be passed on the command line.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvAddr            = "AEGISFLOW_ADDR"
	EnvLogLevel        = "AEGISFLOW_LOG_LEVEL"
	EnvShutdownTimeout = "AEGISFLOW_SHUTDOWN_TIMEOUT"
	EnvDatabaseURL     = "AEGISFLOW_DATABASE_URL"

	// GitHub Actions OIDC (evidence ingestion). Ingestion is enabled when the audience is set
	// together with at least one numeric allow-list, and a database is configured.
	EnvOIDCAudience            = "AEGISFLOW_OIDC_AUDIENCE"
	EnvOIDCRepositoryIDs       = "AEGISFLOW_OIDC_ALLOWED_REPOSITORY_IDS"
	EnvOIDCOwnerIDs            = "AEGISFLOW_OIDC_ALLOWED_OWNER_IDS"
	EnvOIDCAllowedRefs         = "AEGISFLOW_OIDC_ALLOWED_REFS"
	EnvOIDCAllowedEnvironments = "AEGISFLOW_OIDC_ALLOWED_ENVIRONMENTS"
	EnvOIDCIssuer              = "AEGISFLOW_OIDC_ISSUER"

	// Vulnerability intelligence feeds (CISA KEV, FIRST EPSS bulk CSV).
	EnvIntelKEVURL          = "AEGISFLOW_INTEL_KEV_URL"
	EnvIntelEPSSURL         = "AEGISFLOW_INTEL_EPSS_URL"
	EnvIntelRefreshInterval = "AEGISFLOW_INTEL_REFRESH_INTERVAL"

	// EnvDefaultExposure is the deployment exposure assumed for every artifact when scoring
	// risk: internet, internal, build or unknown (default; scored conservatively and flagged).
	EnvDefaultExposure = "AEGISFLOW_DEFAULT_EXPOSURE"

	// EnvDevReadOnlyAPI enables the read-only findings API for loopback clients only. It is a
	// local-development switch: Phase 4 puts the read API behind Entra ID authentication.
	EnvDevReadOnlyAPI = "AEGISFLOW_DEV_READONLY_API"
)

// Defaults applied when a variable is unset or empty.
const (
	DefaultAddr            = ":8080"
	DefaultLogLevel        = "info"
	DefaultShutdownTimeout = 10 * time.Second

	DefaultIntelRefreshInterval = 24 * time.Hour
	DefaultExposure             = "unknown"

	maxShutdownTimeout      = 5 * time.Minute
	minIntelRefreshInterval = time.Minute
	maxIntelRefreshInterval = 7 * 24 * time.Hour
	maxListEntries          = 64
	maxAudienceLen          = 256
)

// Exposure values accepted by AEGISFLOW_DEFAULT_EXPOSURE (risk.Exposure names).
var validExposures = map[string]bool{"internet": true, "internal": true, "build": true, "unknown": true}

// OIDCConfig configures GitHub Actions OIDC verification for /api/v1/ingest. It is turned into a
// ghoidc.Config at startup, which performs the security validation (audience rules, issuer URL).
type OIDCConfig struct {
	// Issuer overrides the expected token issuer ("" = GitHub's default issuer).
	Issuer string
	// Audience is AegisFlow's custom audience; "" disables ingestion.
	Audience string
	// AllowedRepositoryIDs / AllowedOwnerIDs are numeric GitHub IDs (never names).
	AllowedRepositoryIDs []int64
	AllowedOwnerIDs      []int64
	// AllowedRefs / AllowedEnvironments optionally restrict ref and environment (exact match).
	AllowedRefs         []string
	AllowedEnvironments []string
}

// Enabled reports whether OIDC verification is configured.
func (o OIDCConfig) Enabled() bool { return o.Audience != "" }

// IntelConfig configures the vulnerability-intelligence refresher.
type IntelConfig struct {
	// KEVURL is the CISA KEV JSON catalogue URL ("" = the official CISA feed).
	KEVURL string
	// EPSSURL is the EPSS bulk CSV URL ("" = FIRST's documented daily file).
	EPSSURL string
	// RefreshInterval is how often both feeds are refreshed; 0 disables the refresher.
	RefreshInterval time.Duration
}

// Config is the validated runtime configuration.
type Config struct {
	// Addr is the TCP listen address, e.g. ":8080" or "127.0.0.1:8080".
	Addr string
	// LogLevel is the minimum slog level for the JSON logger.
	LogLevel slog.Level
	// ShutdownTimeout bounds graceful shutdown after SIGINT/SIGTERM.
	ShutdownTimeout time.Duration
	// DatabaseURL is the PostgreSQL connection URL (postgres:// or postgresql://). Empty means
	// no database: persistence-backed features are disabled. It may embed credentials, so never
	// log it; use RedactedDatabaseURL.
	DatabaseURL string
	// OIDC configures CI authentication for evidence ingestion.
	OIDC OIDCConfig
	// Intel configures the KEV/EPSS feed refresher.
	Intel IntelConfig
	// DefaultExposure is the risk-engine exposure for all artifacts (internet, internal, build,
	// unknown).
	DefaultExposure string
	// DevReadOnlyAPI enables GET /api/v1/findings* for loopback clients (local development).
	DevReadOnlyAPI bool
}

// IngestEnabled reports whether evidence ingestion can run: it needs a database and OIDC.
func (c Config) IngestEnabled() bool { return c.DatabaseURL != "" && c.OIDC.Enabled() }

// Load reads and validates configuration. getenv is usually os.Getenv; tests inject a map.
// All validation problems are reported together.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr: DefaultAddr, LogLevel: slog.LevelInfo, ShutdownTimeout: DefaultShutdownTimeout,
		Intel:           IntelConfig{RefreshInterval: DefaultIntelRefreshInterval},
		DefaultExposure: DefaultExposure,
	}
	var errs []error

	if v := strings.TrimSpace(getenv(EnvAddr)); v != "" {
		cfg.Addr = v
	}
	if err := validateAddr(cfg.Addr); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvAddr, err))
	}

	if v := strings.TrimSpace(getenv(EnvLogLevel)); v != "" {
		level, err := parseLevel(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvLogLevel, err))
		}
		cfg.LogLevel = level
	}

	if v := strings.TrimSpace(getenv(EnvShutdownTimeout)); v != "" {
		d, err := time.ParseDuration(v)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: invalid duration %q (use e.g. 10s, 1m)", EnvShutdownTimeout, v))
		case d <= 0 || d > maxShutdownTimeout:
			errs = append(errs, fmt.Errorf("%s: %s out of range (0, %s]", EnvShutdownTimeout, d, maxShutdownTimeout))
		default:
			cfg.ShutdownTimeout = d
		}
	}

	if v := strings.TrimSpace(getenv(EnvDatabaseURL)); v != "" {
		if err := validateDatabaseURL(v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvDatabaseURL, err))
		} else {
			cfg.DatabaseURL = v
		}
	}

	errs = append(errs, loadOIDC(getenv, &cfg.OIDC)...)
	errs = append(errs, loadIntel(getenv, &cfg.Intel)...)

	if v := strings.ToLower(strings.TrimSpace(getenv(EnvDefaultExposure))); v != "" {
		if !validExposures[v] {
			errs = append(errs, fmt.Errorf("%s: unknown exposure %q (want internet, internal, build or unknown)",
				EnvDefaultExposure, truncateValue(v)))
		} else {
			cfg.DefaultExposure = v
		}
	}

	if v := strings.TrimSpace(getenv(EnvDevReadOnlyAPI)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: want true or false", EnvDevReadOnlyAPI))
		}
		cfg.DevReadOnlyAPI = b
	}

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

// loadOIDC reads the OIDC variables. A partial configuration (allow-lists without an audience or
// the reverse) is an error rather than silently disabling ingestion.
func loadOIDC(getenv func(string) string, o *OIDCConfig) []error {
	var errs []error
	o.Audience = strings.TrimSpace(getenv(EnvOIDCAudience))
	if o.Audience != "" && (len(o.Audience) > maxAudienceLen ||
		strings.ContainsFunc(o.Audience, func(r rune) bool { return r <= ' ' || r == 0x7f })) {
		errs = append(errs, fmt.Errorf("%s: must be at most %d bytes without spaces or control characters",
			EnvOIDCAudience, maxAudienceLen))
	}
	var err error
	if o.AllowedRepositoryIDs, err = parseIDList(getenv(EnvOIDCRepositoryIDs)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvOIDCRepositoryIDs, err))
	}
	if o.AllowedOwnerIDs, err = parseIDList(getenv(EnvOIDCOwnerIDs)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvOIDCOwnerIDs, err))
	}
	if o.AllowedRefs, err = parseList(getenv(EnvOIDCAllowedRefs)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvOIDCAllowedRefs, err))
	}
	if o.AllowedEnvironments, err = parseList(getenv(EnvOIDCAllowedEnvironments)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvOIDCAllowedEnvironments, err))
	}
	o.Issuer = strings.TrimSpace(getenv(EnvOIDCIssuer))
	if o.Issuer != "" {
		if err := validateFeedURL(o.Issuer); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvOIDCIssuer, err))
		}
	}
	hasLists := len(o.AllowedRepositoryIDs) > 0 || len(o.AllowedOwnerIDs) > 0
	switch {
	case o.Audience != "" && !hasLists:
		errs = append(errs, fmt.Errorf("%s is set: set %s and/or %s (numeric GitHub IDs) as well",
			EnvOIDCAudience, EnvOIDCRepositoryIDs, EnvOIDCOwnerIDs))
	case o.Audience == "" && (hasLists || len(o.AllowedRefs) > 0 || len(o.AllowedEnvironments) > 0 || o.Issuer != ""):
		errs = append(errs, fmt.Errorf("OIDC allow-lists or issuer are set without %s", EnvOIDCAudience))
	}
	return errs
}

func loadIntel(getenv func(string) string, in *IntelConfig) []error {
	var errs []error
	for _, f := range []struct {
		env string
		dst *string
	}{{EnvIntelKEVURL, &in.KEVURL}, {EnvIntelEPSSURL, &in.EPSSURL}} {
		v := strings.TrimSpace(getenv(f.env))
		if v == "" {
			continue
		}
		if err := validateFeedURL(v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.env, err))
			continue
		}
		*f.dst = v
	}
	if v := strings.TrimSpace(getenv(EnvIntelRefreshInterval)); v != "" {
		d, err := time.ParseDuration(v)
		switch {
		case v == "0":
			in.RefreshInterval = 0
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: invalid duration %q (use e.g. 24h, or 0 to disable)",
				EnvIntelRefreshInterval, truncateValue(v)))
		case d < minIntelRefreshInterval || d > maxIntelRefreshInterval:
			errs = append(errs, fmt.Errorf("%s: %s out of range [%s, %s] (0 disables)",
				EnvIntelRefreshInterval, d, minIntelRefreshInterval, maxIntelRefreshInterval))
		default:
			in.RefreshInterval = d
		}
	}
	return errs
}

// parseIDList parses a comma-separated list of positive decimal int64 IDs ("" = empty list).
func parseIDList(raw string) ([]int64, error) {
	items, err := parseList(raw)
	if err != nil || len(items) == 0 {
		return nil, err
	}
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		id, err := strconv.ParseInt(item, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != item {
			return nil, fmt.Errorf("%q is not a positive decimal ID", truncateValue(item))
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// parseList splits a comma-separated list, trimming spaces; empty items are rejected.
func parseList(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxListEntries {
		return nil, fmt.Errorf("more than %d entries", maxListEntries)
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, errors.New("empty list entry")
		}
		if strings.ContainsFunc(p, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			return nil, errors.New("control characters are not allowed")
		}
		out = append(out, p)
	}
	return out, nil
}

// validateFeedURL accepts https URLs, or http on a loopback host (tests, local mirrors), without
// credentials. The packages that use the URL re-validate it.
func validateFeedURL(raw string) error {
	if len(raw) > 2048 || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("must be a URL of at most 2048 bytes without spaces")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("not an absolute URL")
	}
	if u.User != nil {
		return errors.New("must not contain credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip, err := netip.ParseAddr(host); host == "localhost" || (err == nil && ip.IsLoopback()) {
			return nil
		}
		return errors.New("plain http is only allowed for loopback hosts")
	default:
		return errors.New("scheme must be https")
	}
}

// truncateValue shortens an echoed (non-secret) value for error messages.
func truncateValue(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// validSSLModes are libpq's sslmode values.
var validSSLModes = map[string]bool{
	"disable": true, "allow": true, "prefer": true, "require": true, "verify-ca": true, "verify-full": true,
}

// validateDatabaseURL checks the shape of a PostgreSQL URL. Error messages never quote the value:
// it may contain a password.
func validateDatabaseURL(raw string) error {
	if strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("must not contain spaces or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil { // url.Error quotes the input: do not wrap it
		return errors.New("not a valid URL (want postgres://user@host:port/dbname?sslmode=...)")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return errors.New("scheme must be postgres:// or postgresql://")
	}
	q := u.Query()
	if u.Host == "" && q.Get("host") == "" {
		return errors.New("missing host")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return errors.New("invalid port")
		}
	}
	if mode := q.Get("sslmode"); mode != "" && !validSSLModes[mode] {
		return errors.New("invalid sslmode (want disable, allow, prefer, require, verify-ca or verify-full)")
	}
	return nil
}

// RedactedDatabaseURL returns DatabaseURL with any password replaced by "xxxxx", safe to log;
// "" when no database is configured.
func (c Config) RedactedDatabaseURL() string {
	if c.DatabaseURL == "" {
		return ""
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return "(unparseable)"
	}
	return u.Redacted()
}

func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q (want host:port or :port): %w", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("invalid port %q in %q", port, addr)
	}
	if host != "" && host != "localhost" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid host %q in %q (use an IP literal, localhost, or leave empty)", host, addr)
		}
	}
	return nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
	}
}

// HealthcheckURL returns the loopback URL of the liveness endpoint for the configured
// listen address. Used by `aegisflow -healthcheck` inside the distroless container.
func (c Config) HealthcheckURL() string {
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil {
		host, port = "", "8080"
	}
	if host == "" || host == "localhost" {
		host = "127.0.0.1"
	} else if ip, err := netip.ParseAddr(host); err == nil && ip.IsUnspecified() {
		if ip.Is4() {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}
