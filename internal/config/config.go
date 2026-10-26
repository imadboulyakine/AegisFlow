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
)

// Defaults applied when a variable is unset or empty.
const (
	DefaultAddr            = ":8080"
	DefaultLogLevel        = "info"
	DefaultShutdownTimeout = 10 * time.Second

	maxShutdownTimeout = 5 * time.Minute
)

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
}

// Load reads and validates configuration. getenv is usually os.Getenv; tests inject a map.
// All validation problems are reported together.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{Addr: DefaultAddr, LogLevel: slog.LevelInfo, ShutdownTimeout: DefaultShutdownTimeout}
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

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
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
