// Package server wires the AegisFlow HTTP surface: health probes, the versioned JSON
// API and the embedded single-page dashboard, behind a hardened middleware chain.
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/auth/ghoidc"
	"github.com/imadboulyakine/aegisflow/internal/config"
	"github.com/imadboulyakine/aegisflow/internal/version"
)

// Timeouts and limits for the HTTP server. They protect against slow-loris style
// clients and oversized headers; tune them only together with the ingress settings.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 64 << 10 // 64 KiB
	maxBodyBytes      = 1 << 20  // 1 MiB; only POST /api/v1/ingest accepts more (limitBody)
	readyCheckTimeout = 2 * time.Second
)

// Options holds the dependencies of a Server. Zero values select sensible defaults.
type Options struct {
	// Logger receives access and lifecycle logs. Nil discards logs.
	Logger *slog.Logger
	// Static is the built web UI (index.html + assets). Nil or missing index.html
	// serves a small fallback page instead.
	Static fs.FS
	// Version overrides the build metadata (tests). Zero value uses version.Get().
	Version version.Info

	// Verifier authenticates CI uploads (GitHub Actions OIDC). Together with Ingester it enables
	// POST /api/v1/ingest; when either is nil the route answers 503.
	Verifier *ghoidc.Verifier
	// Ingester stores and scores uploaded evidence.
	Ingester Ingester
	// Findings serves the read API (enabled only with cfg.DevReadOnlyAPI). Nil answers 503.
	Findings FindingsReader
	// Ready is an optional dependency check for /readyz (e.g. a database ping).
	Ready func(context.Context) error
}

// Server is the AegisFlow HTTP server.
type Server struct {
	cfg     config.Config
	logger  *slog.Logger
	version version.Info
	ready   atomic.Bool
	handler http.Handler
	http    *http.Server

	verifier *ghoidc.Verifier
	ingester Ingester
	findings FindingsReader
	readyDep func(context.Context) error
}

// New builds a Server; it does not start listening.
func New(cfg config.Config, opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	info := opts.Version
	if info == (version.Info{}) {
		info = version.Get()
	}
	spa, err := newSPAHandler(opts.Static)
	if err != nil {
		return nil, fmt.Errorf("load web UI: %w", err)
	}

	s := &Server{
		cfg: cfg, logger: logger, version: info,
		verifier: opts.Verifier, ingester: opts.Ingester, findings: opts.Findings, readyDep: opts.Ready,
	}
	s.handler = s.newHandler(spa)
	s.http = &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	return s, nil
}

// Handler returns the fully wrapped root handler (useful for tests and embedding).
func (s *Server) Handler() http.Handler { return s.handler }

// newHandler registers routes and applies the middleware chain (outermost first).
func (s *Server) newHandler(spa http.Handler) http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/version", s.handleVersion)
	api.Handle("POST "+ingestPath, s.ingestHandler())
	api.Handle("GET /api/v1/findings", s.readAPI(s.handleListFindings))
	api.Handle("GET /api/v1/findings/{id}", s.readAPI(s.handleGetFinding))
	apiHandler := apiErrors(api)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.Handle("/api/", apiHandler)
	mux.Handle("/api", apiHandler)
	// "/" (any method) rather than "GET /": the SPA handler answers 405 itself, and a
	// method-less pattern avoids ServeMux conflicts with the method-less "/api/" tree.
	mux.Handle("/", spa)

	csrf := http.NewCrossOriginProtection()
	csrf.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, http.StatusForbidden, "Cross-origin request rejected.")
	}))

	return chain(mux,
		requestID,
		securityHeaders,
		accessLog(s.logger),
		recoverPanics(s.logger),
		csrf.Handler, // rejects cross-site unsafe-method requests (Sec-Fetch-Site / Origin)
		limitBody,    // 1 MiB, except POST /api/v1/ingest
	)
}

// ListenAndServe listens on cfg.Addr and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled, then drains in-flight
// requests within cfg.ShutdownTimeout. Readiness flips to "not ready" first so load
// balancers stop routing new traffic while existing requests complete.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.http.Serve(ln) }()
	s.ready.Store(true)
	s.logger.Info("http server listening", slog.String("addr", ln.Addr().String()))

	select {
	case err := <-errCh:
		s.ready.Store(false)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	s.ready.Store(false)
	s.logger.Info("shutting down", slog.String("timeout", s.cfg.ShutdownTimeout.String()))
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ShutdownTimeout)
	defer cancel()
	if err := s.http.Shutdown(shutdownCtx); err != nil {
		_ = s.http.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	s.logger.Info("shutdown complete")
	return nil
}
