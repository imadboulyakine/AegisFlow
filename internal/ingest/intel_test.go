package ingest

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/intel"
)

func intelFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "intel", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type feedServer struct {
	kevStatus, epssStatus atomic.Int32
	kevBody               atomic.Value // []byte
	hits                  atomic.Int32
	srv                   *httptest.Server
}

func newFeedServer(t *testing.T) *feedServer {
	t.Helper()
	fs := &feedServer{}
	fs.kevStatus.Store(http.StatusOK)
	fs.epssStatus.Store(http.StatusOK)
	fs.kevBody.Store(intelFixture(t, "kev_trimmed.json"))
	epss := intelFixture(t, "epss_scores.csv")
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.hits.Add(1)
		switch r.URL.Path {
		case "/kev.json":
			w.WriteHeader(int(fs.kevStatus.Load()))
			_, _ = w.Write(fs.kevBody.Load().([]byte))
		case "/epss.csv":
			w.WriteHeader(int(fs.epssStatus.Load()))
			_, _ = w.Write(epss)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *feedServer) refresher(logs *bytes.Buffer) *Refresher {
	httpOpts := intel.HTTPOptions{Retry: intel.RetryPolicy{MaxAttempts: 1}}
	return &Refresher{
		Store:  intel.NewMemoryStore(intel.NewSnapshot()),
		KEV:    &intel.KEVClient{URL: fs.srv.URL + "/kev.json", HTTP: httpOpts},
		EPSS:   &intel.EPSSClient{BulkURL: fs.srv.URL + "/epss.csv", HTTP: httpOpts},
		Logger: slog.New(slog.NewJSONHandler(logs, nil)),
		now:    func() time.Time { return time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC) },
	}
}

func TestRefresherKeepsLastGoodSnapshot(t *testing.T) {
	t.Parallel()
	fs := newFeedServer(t)
	var logs bytes.Buffer
	r := fs.refresher(&logs)
	if err := r.RefreshOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if in := r.Store.Lookup("CVE-2021-44228"); !in.KEVChecked || !in.KEV {
		t.Fatalf("Log4Shell not in KEV after refresh: %+v", in)
	}
	if in := r.Store.Lookup("CVE-2014-0160"); !in.EPSSKnown || in.EPSS <= 0.9 {
		t.Fatalf("EPSS not loaded: %+v", in)
	}
	if !strings.Contains(logs.String(), `"msg":"intel feed refreshed"`) || !strings.Contains(logs.String(), `"feed":"epss"`) {
		t.Errorf("logs = %s", logs.String())
	}

	// Upstream failure, then an empty (truncated or tampered) catalogue: both keep the snapshot.
	fs.kevStatus.Store(http.StatusBadGateway)
	fs.epssStatus.Store(http.StatusInternalServerError)
	if err := r.RefreshOnce(t.Context()); err == nil || !strings.Contains(err.Error(), "kev") || !strings.Contains(err.Error(), "epss") {
		t.Fatalf("RefreshOnce() = %v, want both feeds to fail", err)
	}
	fs.kevStatus.Store(http.StatusOK)
	fs.kevBody.Store([]byte(`{"title":"x","catalogVersion":"1","dateReleased":"2026-10-26T00:00:00Z","count":0,"vulnerabilities":[]}`))
	if err := r.RefreshOnce(t.Context()); err == nil {
		t.Fatal("empty catalogue accepted")
	}
	if in := r.Store.Lookup("CVE-2021-44228"); !in.KEV {
		t.Fatal("a failed refresh erased the KEV signal")
	}
	if !strings.Contains(logs.String(), "keeping the previous snapshot") {
		t.Errorf("logs = %s", logs.String())
	}
}

func TestRefresherRunAndCancel(t *testing.T) {
	t.Parallel()
	fs := newFeedServer(t)
	var logs bytes.Buffer
	r := fs.refresher(&logs)
	r.Interval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for fs.hits.Load() < 4 { // initial refresh (2 feeds) + at least one tick
		if time.Now().After(deadline) {
			t.Fatal("refresher did not tick")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// A disabled refresher returns immediately; a refresher without a store errors.
	(&Refresher{}).Run(t.Context())
	if err := (&Refresher{}).RefreshOnce(t.Context()); err == nil {
		t.Error("RefreshOnce without store succeeded")
	}
	// Cancellation is reported without a warning.
	cctx, ccancel := context.WithCancel(t.Context())
	ccancel()
	var quiet bytes.Buffer
	if err := fs.refresher(&quiet).RefreshOnce(cctx); err == nil || strings.Contains(quiet.String(), "refresh failed") {
		t.Errorf("cancelled refresh = %v, logs %s", err, quiet.String())
	}
	if (&Refresher{}).clock().IsZero() || (&Refresher{}).logger() == nil {
		t.Error("defaults")
	}
}
