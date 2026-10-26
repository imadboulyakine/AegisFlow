package intel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultUserAgent identifies AegisFlow to feed providers.
const DefaultUserAgent = "aegisflow-intel/1 (+https://github.com/imadboulyakine/aegisflow)"

// Retry defaults and hard bounds.
const (
	DefaultMaxAttempts = 4
	MaxAttemptsLimit   = 10
	DefaultBaseDelay   = 500 * time.Millisecond
	DefaultMaxDelay    = 10 * time.Second
	// defaultHTTPTimeout bounds one whole request (connect, headers, body).
	defaultHTTPTimeout = 60 * time.Second
	maxRedirects       = 5
)

// ErrTooLarge is returned when a response or decompressed document exceeds its size limit.
var ErrTooLarge = errors.New("exceeds size limit")

// HTTPStatusError reports a response with a status other than 200 OK.
type HTTPStatusError struct {
	// URL is the request URL without its query string.
	URL        string
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("GET %s: unexpected status %d %s", e.URL, e.StatusCode, http.StatusText(e.StatusCode))
}

// Retryable reports whether the status is worth retrying (429 or 5xx).
func (e *HTTPStatusError) Retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= http.StatusInternalServerError
}

// RetryPolicy bounds retries of transient failures: 429 and 5xx responses and transport errors.
// Delays grow exponentially (BaseDelay, 2×BaseDelay, ...) up to MaxDelay; a Retry-After header
// lengthens the wait but never beyond MaxDelay. Zero fields take the defaults.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts, including the first (default 4, max 10).
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func (p RetryPolicy) normalized() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = DefaultMaxAttempts
	}
	p.MaxAttempts = min(p.MaxAttempts, MaxAttemptsLimit)
	if p.BaseDelay <= 0 {
		p.BaseDelay = DefaultBaseDelay
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = DefaultMaxDelay
	}
	p.MaxDelay = max(p.MaxDelay, p.BaseDelay)
	return p
}

// backoff returns the wait before the attempt following failed attempt number n (0-based).
func (p RetryPolicy) backoff(n int, retryAfter time.Duration) time.Duration {
	d := p.BaseDelay
	for range n {
		if d > p.MaxDelay/2 {
			d = p.MaxDelay
			break
		}
		d *= 2
	}
	return min(max(d, retryAfter), p.MaxDelay)
}

// HTTPOptions configures how the feed clients talk HTTP.
type HTTPOptions struct {
	// Client performs requests. Nil uses a client with a 60 s overall timeout that follows at
	// most 5 redirects and refuses https→http downgrades. Proxies come from the environment.
	Client *http.Client
	// UserAgent is sent with every request; empty uses DefaultUserAgent.
	UserAgent string
	// Retry bounds retries of transient failures.
	Retry RetryPolicy
}

var defaultClient = &http.Client{
	Timeout: defaultHTTPTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("refusing redirect from https to " + req.URL.Scheme)
		}
		return nil
	},
}

// get fetches rawURL and returns its body (at most maxBytes), retrying transient failures.
func (o HTTPOptions) get(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	policy := o.Retry.normalized()
	var lastErr error
	for attempt := range policy.MaxAttempts {
		body, retryAfter, retry, err := o.do(ctx, rawURL, maxBytes)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil || attempt == policy.MaxAttempts-1 {
			break
		}
		if err := sleep(ctx, policy.backoff(attempt, retryAfter)); err != nil {
			return nil, fmt.Errorf("%w (last error: %w)", err, lastErr)
		}
	}
	return nil, lastErr
}

// do performs one attempt. retry reports whether the failure is transient.
func (o HTTPOptions) do(ctx context.Context, rawURL string, maxBytes int64) (body []byte, retryAfter time.Duration, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, false, fmt.Errorf("build request: %w", err)
	}
	ua := o.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	req.Header.Set("User-Agent", ua)
	client := o.Client
	if client == nil {
		client = defaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// Transport errors (resets, timeouts) are transient unless the caller gave up.
		return nil, 0, ctx.Err() == nil, fmt.Errorf("GET %s: %w", redactURL(rawURL), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		se := &HTTPStatusError{URL: redactURL(rawURL), StatusCode: resp.StatusCode}
		return nil, parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()), se.Retryable(), se
	}
	if resp.ContentLength > maxBytes {
		return nil, 0, false, fmt.Errorf("GET %s: body of %d bytes %w of %d bytes", redactURL(rawURL), resp.ContentLength, ErrTooLarge, maxBytes)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, 0, ctx.Err() == nil, fmt.Errorf("GET %s: read body: %w", redactURL(rawURL), err)
	}
	if int64(len(body)) > maxBytes {
		return nil, 0, false, fmt.Errorf("GET %s: body %w of %d bytes", redactURL(rawURL), ErrTooLarge, maxBytes)
	}
	return body, 0, false, nil
}

// parseRetryAfter interprets a Retry-After header (delta-seconds or HTTP-date); 0 if absent or invalid.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		const maxSecs = int64(24 * time.Hour / time.Second)
		return time.Duration(min(secs, maxSecs)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("retry wait: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

// redactURL drops the query and any user info so error messages stay short and credential-free.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// validateFeedURL accepts https URLs, and http only for loopback hosts (local mirrors, tests).
// URLs carrying credentials are rejected: feeds are public and secrets never go in URLs.
func validateFeedURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid feed URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid feed URL %q: missing host", redactURL(raw))
	}
	if u.User != nil {
		return nil, errors.New("invalid feed URL: credentials in URLs are not allowed")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("invalid feed URL %q: plain http is only allowed for loopback hosts", redactURL(raw))
		}
	default:
		return nil, fmt.Errorf("invalid feed URL %q: scheme must be https", redactURL(raw))
	}
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// readLimited reads all of r, failing with ErrTooLarge beyond limit bytes.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("input %w of %d bytes", ErrTooLarge, limit)
	}
	return b, nil
}
