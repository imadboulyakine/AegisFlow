package ingest

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/intel"
)

// Refresher keeps an intel.MemoryStore current by downloading the CISA KEV catalogue and the
// EPSS bulk CSV on a fixed interval. A failed or rejected download keeps the previous snapshot
// (the intel parsers refuse empty or inconsistent feeds), so an outage or a tampered feed never
// erases the "exploited" signal; it is logged and retried at the next tick.
type Refresher struct {
	// Store receives the feeds. Required.
	Store *intel.MemoryStore
	// KEV and EPSS download the feeds; nil skips that feed.
	KEV  *intel.KEVClient
	EPSS *intel.EPSSClient
	// Interval between refreshes; Run refreshes once immediately, then every Interval.
	Interval time.Duration
	// Logger receives one line per feed and attempt. Nil discards.
	Logger *slog.Logger
	// now is replaceable in tests.
	now func() time.Time
}

func (r *Refresher) logger() *slog.Logger {
	if r.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Logger
}

func (r *Refresher) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now().UTC()
}

// RefreshOnce downloads every configured feed once. Feeds are independent: a KEV failure does not
// prevent the EPSS update. The returned error joins the per-feed failures.
func (r *Refresher) RefreshOnce(ctx context.Context) error {
	if r.Store == nil {
		return errors.New("intel refresher: no store")
	}
	var errs []error
	if r.KEV != nil {
		source := cmp.Or(r.KEV.URL, intel.DefaultKEVURL)
		cat, err := r.KEV.Fetch(ctx)
		if err == nil {
			err = r.Store.UpdateKEV(cat, source, r.clock())
		}
		errs = append(errs, r.report(ctx, intel.FeedKEV, err))
	}
	if r.EPSS != nil {
		source := cmp.Or(r.EPSS.BulkURL, intel.DefaultEPSSBulkURL)
		ds, err := r.EPSS.Bulk(ctx)
		if err == nil {
			err = r.Store.UpdateEPSS(ds, source, r.clock())
		}
		errs = append(errs, r.report(ctx, intel.FeedEPSS, err))
	}
	return errors.Join(errs...)
}

// report logs the outcome of one feed refresh and returns the wrapped error (nil on success).
func (r *Refresher) report(ctx context.Context, feed string, err error) error {
	log := r.logger()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s: %w", feed, ctx.Err())
		}
		log.LogAttrs(ctx, slog.LevelWarn, "intel feed refresh failed; keeping the previous snapshot",
			slog.String("feed", feed), slog.String("error", err.Error()))
		return fmt.Errorf("%s: %w", feed, err)
	}
	for _, f := range r.Store.Feeds() {
		if f.Name != feed {
			continue
		}
		log.LogAttrs(ctx, slog.LevelInfo, "intel feed refreshed",
			slog.String("feed", f.Name), slog.String("source", f.Source), slog.String("version", f.Version),
			slog.Time("date", f.Date), slog.Int("entries", f.Entries))
	}
	return nil
}

// Run refreshes immediately and then every Interval until ctx is cancelled. It returns when ctx
// is done; in-flight downloads observe ctx.
func (r *Refresher) Run(ctx context.Context) {
	if r.Interval <= 0 {
		return
	}
	_ = r.RefreshOnce(ctx)
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.RefreshOnce(ctx)
		}
	}
}
