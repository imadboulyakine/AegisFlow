package intel

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Fixtures (testdata/):
//   - kev_trimmed.json: 21 real entries of the CISA KEV catalogue 2026.10.23, downloaded once
//     from KEVMirrorURL and trimmed with jq (count adjusted); all fields kept verbatim.
//   - epss_api_response.json, epss_scores.csv: hand-built from FIRST's documented API v1 and
//     bulk-CSV schemas (api.first.org is unreachable from the development container); the
//     scores are synthetic but plausible.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func mustDate(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := parseDate(s)
	if err != nil {
		t.Fatalf("parse date %q: %v", s, err)
	}
	return d
}

// fastRetry keeps retry tests quick.
var fastRetry = RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}

func TestParseKEVFixture(t *testing.T) {
	t.Parallel()
	cat, err := ParseKEV(bytes.NewReader(readFixture(t, "kev_trimmed.json")))
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	if cat.CatalogVersion != "2026.10.23" || cat.Count != 21 || len(cat.Vulnerabilities) != 21 {
		t.Fatalf("catalog header = %q count %d len %d", cat.CatalogVersion, cat.Count, len(cat.Vulnerabilities))
	}
	if want := time.Date(2026, 10, 23, 19, 30, 18, 920900000, time.UTC); !cat.DateReleased.Equal(want) {
		t.Errorf("DateReleased = %v, want %v", cat.DateReleased, want)
	}
	if cat.Title == "" {
		t.Error("Title empty")
	}
	byID := map[string]KEVEntry{}
	ransomware := 0
	for _, e := range cat.Vulnerabilities {
		byID[e.CVEID] = e
		if e.RansomwareKnown() {
			ransomware++
		}
	}
	if ransomware != 11 {
		t.Errorf("ransomware-known entries = %d, want 11", ransomware)
	}
	log4j, ok := byID["CVE-2021-44228"]
	if !ok {
		t.Fatal("CVE-2021-44228 missing")
	}
	if !log4j.DateAdded.Equal(mustDate(t, "2021-12-10")) || !log4j.DueDate.Equal(mustDate(t, "2021-12-24")) {
		t.Errorf("log4j dates = %v / %v", log4j.DateAdded, log4j.DueDate)
	}
	if !log4j.RansomwareKnown() || log4j.VendorProject != "Apache" || len(log4j.CWEs) == 0 {
		t.Errorf("log4j entry = %+v", log4j)
	}
	if _, ok := byID["CVE-2026-114625"]; !ok {
		t.Error("6-digit CVE sequence not accepted")
	}
	if byID["CVE-2023-44487"].RansomwareKnown() {
		t.Error("CVE-2023-44487 should not be ransomware-known")
	}
}

const minimalKEV = `{"title":"t","catalogVersion":"2026.01.02","dateReleased":"2026-01-02T03:04:05Z","count":1,
"vulnerabilities":[{"cveID":" cve-2024-3400 ","dateAdded":"2024-04-12","dueDate":"","knownRansomwareCampaignUse":"Known","newField":true}]}`

func TestParseKEVLenient(t *testing.T) {
	t.Parallel()
	cat, err := ParseKEV(strings.NewReader(minimalKEV))
	if err != nil {
		t.Fatalf("ParseKEV: %v", err)
	}
	e := cat.Vulnerabilities[0]
	if e.CVEID != "CVE-2024-3400" || !e.DueDate.IsZero() || !e.RansomwareKnown() {
		t.Errorf("entry = %+v", e)
	}
}

func TestParseKEVErrors(t *testing.T) {
	t.Parallel()
	entry := func(fields string) string {
		return `{"catalogVersion":"v","dateReleased":"2026-01-02T03:04:05Z","count":1,"vulnerabilities":[{` + fields + `}]}`
	}
	tests := []struct {
		name, in, want string
	}{
		{"not json", "nope", "invalid character"},
		{"trailing garbage", minimalKEV + "x", "invalid character"},
		{"missing version", `{"dateReleased":"2026-01-02T03:04:05Z","count":0,"vulnerabilities":[]}`, "missing catalogVersion"},
		{"bad released", `{"catalogVersion":"v","dateReleased":"yesterday","count":0}`, "dateReleased"},
		{"missing count", `{"catalogVersion":"v","dateReleased":"2026-01-02T03:04:05Z","vulnerabilities":[]}`, "missing count"},
		{"empty", `{"catalogVersion":"v","dateReleased":"2026-01-02T03:04:05Z","count":0,"vulnerabilities":[]}`, "no entries"},
		{"count mismatch", strings.Replace(entry(`"cveID":"CVE-2024-3400","dateAdded":"2024-04-12"`), `"count":1`, `"count":2`, 1), "does not match"},
		{"bad cve", entry(`"cveID":"GHSA-xxxx","dateAdded":"2024-04-12"`), "invalid cveID"},
		{"bad dateAdded", entry(`"cveID":"CVE-2024-3400","dateAdded":"12/04/2024"`), "dateAdded"},
		{"missing dateAdded", entry(`"cveID":"CVE-2024-3400"`), "dateAdded"},
		{"bad dueDate", entry(`"cveID":"CVE-2024-3400","dateAdded":"2024-04-12","dueDate":"soon"`), "dueDate"},
		{"wrong type", entry(`"cveID":42`), "cannot unmarshal"},
		{"duplicate", `{"catalogVersion":"v","dateReleased":"2026-01-02T03:04:05Z","count":2,"vulnerabilities":[
			{"cveID":"CVE-2024-3400","dateAdded":"2024-04-12"},{"cveID":"cve-2024-3400","dateAdded":"2024-04-13"}]}`, "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseKEV(strings.NewReader(tt.in))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParseKEVTooLarge(t *testing.T) {
	t.Parallel()
	big := strings.NewReader(strings.Repeat(" ", int(DefaultKEVMaxBytes)+1))
	if _, err := ParseKEV(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestKEVClientFetch(t *testing.T) {
	t.Parallel()
	fixture := readFixture(t, "kev_trimmed.json")
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if got := r.Header.Get("User-Agent"); got != DefaultUserAgent {
			t.Errorf("User-Agent = %q", got)
		}
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c := &KEVClient{URL: srv.URL + "/kev.json", HTTP: HTTPOptions{Retry: fastRetry}}
	cat, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if cat.Count != 21 || calls.Load() != 2 {
		t.Errorf("count %d after %d calls, want 21 after 2", cat.Count, calls.Load())
	}
}

func TestKEVClientFetchErrors(t *testing.T) {
	t.Parallel()
	fixture := readFixture(t, "kev_trimmed.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			http.NotFound(w, r)
		case "/garbage":
			_, _ = w.Write([]byte(`{"catalogVersion":`))
		default:
			_, _ = w.Write(fixture)
		}
	}))
	t.Cleanup(srv.Close) // not defer: the parallel subtests outlive this function body

	tests := []struct {
		name   string
		client KEVClient
		check  func(error) bool
	}{
		{"not found", KEVClient{URL: srv.URL + "/missing"}, func(err error) bool {
			var se *HTTPStatusError
			return errors.As(err, &se) && se.StatusCode == http.StatusNotFound && !se.Retryable()
		}},
		{"garbage", KEVClient{URL: srv.URL + "/garbage"}, func(err error) bool { return strings.Contains(err.Error(), "parse kev") }},
		{"too large", KEVClient{URL: srv.URL + "/kev.json", MaxBytes: 100}, func(err error) bool { return errors.Is(err, ErrTooLarge) }},
		{"plain http remote", KEVClient{URL: "http://example.com/kev.json"}, func(err error) bool { return strings.Contains(err.Error(), "loopback") }},
		{"ftp", KEVClient{URL: "ftp://127.0.0.1/kev.json"}, func(err error) bool { return strings.Contains(err.Error(), "scheme") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := tt.client.Fetch(context.Background())
			if err == nil || !tt.check(err) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestKEVClientCancelledContext(t *testing.T) {
	t.Parallel()
	// The default URL is https and valid; with a cancelled context no request leaves the process.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &KEVClient{}
	if _, err := c.Fetch(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
