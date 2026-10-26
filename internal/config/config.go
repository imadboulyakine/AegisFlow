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
	"strconv"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvAddr            = "AEGISFLOW_ADDR"
	EnvLogLevel        = "AEGISFLOW_LOG_LEVEL"
	EnvShutdownTimeout = "AEGISFLOW_SHUTDOWN_TIMEOUT"
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

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
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
