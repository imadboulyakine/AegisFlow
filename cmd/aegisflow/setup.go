package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/auth/ghoidc"
	"github.com/imadboulyakine/aegisflow/internal/config"
	"github.com/imadboulyakine/aegisflow/internal/ingest"
	"github.com/imadboulyakine/aegisflow/internal/intel"
	"github.com/imadboulyakine/aegisflow/internal/risk"
	"github.com/imadboulyakine/aegisflow/internal/server"
	"github.com/imadboulyakine/aegisflow/internal/store"
)

// Startup timeouts for dependencies.
const (
	dbStartupTimeout   = 30 * time.Second
	jwksWarmupTimeout  = 10 * time.Second
	refresherStopGrace = 5 * time.Second
)

// dependencies holds what setup built: the server options plus background work and cleanup.
type dependencies struct {
	opts      server.Options
	refresher *ingest.Refresher
	wg        sync.WaitGroup
	cancel    context.CancelFunc
	closers   []func()
}

// start launches background work (the intel refresher) bound to ctx.
func (d *dependencies) start(ctx context.Context) {
	if d.refresher == nil || d.refresher.Interval <= 0 {
		return
	}
	ctx, d.cancel = context.WithCancel(ctx)
	d.wg.Go(func() { d.refresher.Run(ctx) })
}

// close stops background work (bounded wait) and releases resources, in reverse order.
func (d *dependencies) close() {
	if d.cancel != nil {
		d.cancel()
		done := make(chan struct{})
		go func() { d.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(refresherStopGrace):
		}
	}
	for _, closeFn := range slices.Backward(d.closers) {
		closeFn()
	}
}

// setup builds the optional Phase 2 dependencies from cfg:
//   - with AEGISFLOW_DATABASE_URL: the PostgreSQL store (migrated), readiness check and read API;
//   - with the database and OIDC settings: the OIDC verifier, the intel store and its refresher,
//     the risk engine and the ingest service.
//
// Without them the server starts as before (ingest answers 503, the read API is disabled).
// Configuration errors (e.g. a refused audience) and an unreachable database fail startup.
func setup(ctx context.Context, cfg config.Config, logger *slog.Logger) (*dependencies, error) {
	d := &dependencies{}
	var verifier *ghoidc.Verifier
	if cfg.IngestEnabled() {
		// Validate the OIDC configuration before any I/O.
		v, err := ghoidc.NewVerifier(ghoidc.Config{
			Issuer:               cfg.OIDC.Issuer,
			Audience:             cfg.OIDC.Audience,
			AllowedRepositoryIDs: cfg.OIDC.AllowedRepositoryIDs,
			AllowedOwnerIDs:      cfg.OIDC.AllowedOwnerIDs,
			AllowedRefs:          cfg.OIDC.AllowedRefs,
			AllowedEnvironments:  cfg.OIDC.AllowedEnvironments,
		})
		if err != nil {
			return nil, fmt.Errorf("oidc: %w", err)
		}
		verifier = v
	} else if cfg.OIDC.Enabled() {
		logger.Warn("evidence ingestion disabled: OIDC is configured but " + config.EnvDatabaseURL + " is not set")
	}

	if cfg.DatabaseURL == "" {
		return d, nil
	}
	openCtx, cancel := context.WithTimeout(ctx, dbStartupTimeout)
	defer cancel()
	st, err := store.Open(openCtx, cfg.DatabaseURL, store.Options{Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	d.closers = append(d.closers, st.Close)
	mig, err := st.Migrate(openCtx)
	if err != nil {
		d.close()
		return nil, fmt.Errorf("database migrations: %w", err)
	}
	logger.Info("database ready", slog.String("url", cfg.RedactedDatabaseURL()),
		slog.Int("schema_version", mig.Version), slog.Any("applied_migrations", mig.Applied))
	d.opts.Findings = st
	d.opts.Ready = st.Ping

	if verifier == nil {
		return d, nil
	}
	warmCtx, warmCancel := context.WithTimeout(ctx, jwksWarmupTimeout)
	defer warmCancel()
	if err := verifier.Refresh(warmCtx); err != nil {
		// Not fatal: the verifier retries on the first request (and answers 503 meanwhile).
		logger.Warn("oidc signing keys not loaded at startup; will retry on demand", slog.String("error", err.Error()))
	}

	intelStore := intel.NewMemoryStore(intel.NewSnapshot())
	d.refresher = &ingest.Refresher{
		Store:    intelStore,
		KEV:      &intel.KEVClient{URL: cfg.Intel.KEVURL},
		EPSS:     &intel.EPSSClient{BulkURL: cfg.Intel.EPSSURL},
		Interval: cfg.Intel.RefreshInterval,
		Logger:   logger.With(slog.String("component", "intel")),
	}
	if cfg.Intel.RefreshInterval <= 0 {
		logger.Warn("intel refresher disabled: findings are scored without KEV/EPSS data")
	}
	engine, err := risk.NewEngine(risk.DefaultConfig())
	if err != nil {
		d.close()
		return nil, fmt.Errorf("risk engine: %w", err)
	}
	svc, err := ingest.New(ingest.Options{
		Store: st, Engine: engine, Intel: intelStore, Exposure: risk.Exposure(cfg.DefaultExposure),
		Logger: logger.With(slog.String("component", "ingest")),
	})
	if err != nil {
		d.close()
		return nil, err
	}
	d.opts.Verifier = verifier
	d.opts.Ingester = svc
	return d, nil
}
