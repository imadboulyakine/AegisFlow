package intel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeCVE(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"CVE-2021-44228", "CVE-2021-44228", true},
		{" cve-2026-114625\n", "CVE-2026-114625", true},
		{"CVE-1999-0001", "CVE-1999-0001", true},
		{"CVE-2021-123", "", false},
		{"CVE-21-44228", "", false},
		{"CVE-2021-4422a", "", false},
		{"CVE-2021", "", false},
		{"GHSA-jfh8-c2jp-5v3q", "", false},
		{"CVE-2021-" + strings.Repeat("1", 20), "", false},
		{"CVE-2021-" + strings.Repeat("1", 19), "CVE-2021-" + strings.Repeat("1", 19), true},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := NormalizeCVE(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("NormalizeCVE(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-3", 0},
		{"7", 7 * time.Second},
		{"99999999999", 24 * time.Hour},
		{"soon", 0},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	}
	for _, tt := range tests {
		if got := parseRetryAfter(tt.in, now); got != tt.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestRetryPolicy(t *testing.T) {
	t.Parallel()
	p := RetryPolicy{}.normalized()
	if p.MaxAttempts != DefaultMaxAttempts || p.BaseDelay != DefaultBaseDelay || p.MaxDelay != DefaultMaxDelay {
		t.Fatalf("defaults = %+v", p)
	}
	if got := (RetryPolicy{MaxAttempts: 1000}).normalized().MaxAttempts; got != MaxAttemptsLimit {
		t.Errorf("MaxAttempts cap = %d", got)
	}
	if got := (RetryPolicy{BaseDelay: time.Second, MaxDelay: time.Millisecond}).normalized().MaxDelay; got != time.Second {
		t.Errorf("MaxDelay floor = %v", got)
	}
	p = RetryPolicy{BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second}.normalized()
	want := []time.Duration{100, 200, 400, 800, 1000, 1000}
	for n, w := range want {
		if got := p.backoff(n, 0); got != w*time.Millisecond {
			t.Errorf("backoff(%d) = %v, want %v", n, got, w*time.Millisecond)
		}
	}
	if got := p.backoff(0, 500*time.Millisecond); got != 500*time.Millisecond {
		t.Errorf("Retry-After not honoured: %v", got)
	}
	if got := p.backoff(0, time.Hour); got != time.Second {
		t.Errorf("Retry-After not capped: %v", got)
	}
	if got := p.backoff(200, 0); got != time.Second {
		t.Errorf("large n: %v", got)
	}
}

func TestValidateFeedURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in string
		ok bool
	}{
		{DefaultKEVURL, true},
		{KEVMirrorURL, true},
		{DefaultEPSSAPIURL, true},
		{DefaultEPSSBulkURL, true},
		{"http://127.0.0.1:8080/x", true},
		{"http://[::1]/x", true},
		{"http://localhost/x", true},
		{"http://10.0.0.1/x", false},
		{"https://user:pw@example.com/x", false},
		{"https:///nohost", false},
		{"file:///etc/passwd", false},
		{"::not a url", false},
	}
	for _, tt := range tests {
		_, err := validateFeedURL(tt.in)
		if (err == nil) != tt.ok {
			t.Errorf("validateFeedURL(%q) err = %v, want ok=%v", tt.in, err, tt.ok)
		}
	}
}

func TestRedactURL(t *testing.T) {
	t.Parallel()
	if got := redactURL("https://u:p@example.com/a?cve=CVE-1#f"); got != "https://example.com/a" {
		t.Errorf("redactURL = %q", got)
	}
	if got := redactURL("::bad"); got != "<invalid url>" {
		t.Errorf("redactURL(bad) = %q", got)
	}
}

func TestDefaultClientRedirectPolicy(t *testing.T) {
	t.Parallel()
	mk := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	check := defaultClient.CheckRedirect
	if err := check(mk("http://example.com/b"), []*http.Request{mk("https://example.com/a")}); err == nil {
		t.Error("https→http downgrade allowed")
	}
	if err := check(mk("https://mirror.example.com/b"), []*http.Request{mk("https://example.com/a")}); err != nil {
		t.Errorf("https→https refused: %v", err)
	}
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = mk("https://example.com/a" + strconv.Itoa(i))
	}
	if err := check(mk("https://example.com/z"), via); err == nil {
		t.Error("redirect limit not enforced")
	}
}

func TestGetRetriesAndLimits(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch r.URL.Path {
		case "/flaky":
			if n%3 != 0 {
				http.Error(w, "x", http.StatusBadGateway)
				return
			}
			_, _ = w.Write([]byte("ok"))
		case "/always500":
			http.Error(w, "x", http.StatusInternalServerError)
		case "/declared-large":
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write(make([]byte, 1000))
		case "/ua":
			_, _ = w.Write([]byte(r.Header.Get("User-Agent")))
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	o := HTTPOptions{Retry: fastRetry, UserAgent: "custom/1"}
	if b, err := o.get(ctx, srv.URL+"/flaky", 10); err != nil || string(b) != "ok" {
		t.Fatalf("flaky: %q, %v", b, err)
	}
	if b, err := o.get(ctx, srv.URL+"/ua", 100); err != nil || string(b) != "custom/1" {
		t.Errorf("user agent: %q, %v", b, err)
	}

	calls.Store(0)
	_, err := o.get(ctx, srv.URL+"/always500", 10)
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusInternalServerError || !se.Retryable() {
		t.Fatalf("always500: %v", err)
	}
	if got := calls.Load(); got != int32(fastRetry.MaxAttempts) {
		t.Errorf("always500 attempts = %d, want %d", got, fastRetry.MaxAttempts)
	}
	if !strings.Contains(se.Error(), "500 Internal Server Error") {
		t.Errorf("error text = %q", se.Error())
	}

	if _, err := o.get(ctx, srv.URL+"/declared-large", 999); !errors.Is(err, ErrTooLarge) {
		t.Errorf("declared-large: %v", err)
	}
	if _, err := o.get(ctx, "http://127.0.0.1:1/\x7f", 10); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Errorf("bad url: %v", err)
	}
}

func TestGetTransportErrorRetried(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close() // connection refused from now on

	var attempts atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})}
	o := HTTPOptions{Client: client, Retry: fastRetry}
	if _, err := o.get(context.Background(), addr, 10); err == nil {
		t.Fatal("expected error")
	}
	if got := attempts.Load(); got != int32(fastRetry.MaxAttempts) {
		t.Errorf("attempts = %d, want %d", got, fastRetry.MaxAttempts)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGetContextCancelledDuringBackoff(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "x", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	o := HTTPOptions{Retry: RetryPolicy{MaxAttempts: 5, BaseDelay: time.Millisecond, MaxDelay: time.Minute}}
	start := time.Now()
	_, err := o.get(ctx, srv.URL, 10)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	var se *HTTPStatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusTooManyRequests {
		t.Errorf("last error not preserved: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("backoff ignored cancellation")
	}
}

func TestReadLimited(t *testing.T) {
	t.Parallel()
	if b, err := readLimited(strings.NewReader("abc"), 3); err != nil || string(b) != "abc" {
		t.Errorf("at limit: %q %v", b, err)
	}
	if _, err := readLimited(strings.NewReader("abcd"), 3); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over limit: %v", err)
	}
	if _, err := readLimited(errReader{}, 3); err == nil {
		t.Error("read error swallowed")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
