// Command aegisflow runs the AegisFlow DevSecOps platform server: the JSON API,
// health probes and the embedded web dashboard, from a single static binary.
//
// Usage:
//
//	aegisflow               serve on $AEGISFLOW_ADDR (default :8080)
//	aegisflow -healthcheck  probe the local /healthz endpoint; exit 0 if healthy
//	aegisflow -version      print build metadata as JSON
//
// Configuration comes from environment variables only (see internal/config).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/config"
	"github.com/imadboulyakine/aegisflow/internal/server"
	"github.com/imadboulyakine/aegisflow/internal/version"
	"github.com/imadboulyakine/aegisflow/internal/webui"
)

const healthcheckTimeout = 3 * time.Second

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run is main without process-global side effects, so it can be tested.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("aegisflow", flag.ContinueOnError)
	flags.SetOutput(stderr)
	healthcheck := flags.Bool("healthcheck", false, "probe the local /healthz endpoint and exit 0 (healthy) or 1 (unhealthy)")
	showVersion := flags.Bool("version", false, "print build metadata as JSON and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "aegisflow: unexpected arguments: %q\n", flags.Args())
		return exitUsage
	}

	if *showVersion {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(version.Get()); err != nil {
			return exitError
		}
		return exitOK
	}

	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "aegisflow: invalid configuration:\n%v\n", err)
		return exitError
	}

	if *healthcheck {
		return probe(ctx, cfg.HealthcheckURL(), stderr)
	}

	logger := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: cfg.LogLevel})).
		With(slog.String("service", "aegisflow"))

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	static, err := webui.FS()
	if err != nil {
		logger.Error("startup failed", slog.Any("error", err))
		return exitError
	}
	srv, err := server.New(cfg, server.Options{Logger: logger, Static: static})
	if err != nil {
		logger.Error("startup failed", slog.Any("error", err))
		return exitError
	}

	info := version.Get()
	logger.Info("starting aegisflow",
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("build_date", info.BuildDate),
		slog.String("go_version", info.GoVersion),
		slog.String("addr", cfg.Addr),
		slog.String("log_level", cfg.LogLevel.String()),
	)
	if err := srv.ListenAndServe(ctx); err != nil {
		logger.Error("server stopped with error", slog.Any("error", err))
		return exitError
	}
	return exitOK
}

// probe performs the container health check without curl/wget (the runtime image is
// distroless). It never follows redirects and ignores proxy environment variables.
func probe(ctx context.Context, url string, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return exitError
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return exitError
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "healthcheck: %s returned %s\n", url, res.Status)
		return exitError
	}
	return exitOK
}
