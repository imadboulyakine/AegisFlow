package ghoidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// maxJWKSBytes bounds the JWKS response body (GitHub's is a few KiB).
	maxJWKSBytes = 512 << 10
	// maxJWKSKeys bounds the number of JWK entries processed.
	maxJWKSKeys = 64
	minRSABits  = 2048
	maxRSABits  = 8192
	// defaultFetchTimeout bounds one JWKS fetch independently of the HTTP client's own timeout.
	defaultFetchTimeout = 10 * time.Second
)

// keySet is an immutable snapshot of the issuer's usable RS256 verification keys.
type keySet struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// jwksCache holds the last good key set and coordinates refreshes:
//   - at most one fetch runs at a time; concurrent callers wait for it (singleflight);
//   - fetches start at most once per minInterval, whatever triggers them, so a flood of
//     tokens with unknown kids causes at most one request per interval to the issuer;
//   - a failed fetch keeps the previous key set (last known good).
type jwksCache struct {
	url          string
	client       *http.Client
	ttl          time.Duration
	minInterval  time.Duration
	fetchTimeout time.Duration
	now          func() time.Time

	mu          sync.Mutex
	current     *keySet
	lastAttempt time.Time
	lastErr     error
	inflight    chan struct{} // closed when the running fetch completes; nil when idle
}

func newJWKSCache(cfg Config, now func() time.Time) *jwksCache {
	return &jwksCache{
		url:          cfg.JWKSURL,
		client:       cfg.HTTPClient,
		ttl:          cfg.JWKSCacheTTL,
		minInterval:  cfg.JWKSMinRefreshInterval,
		fetchTimeout: defaultFetchTimeout,
		now:          now,
	}
}

// key returns the verification key for kid, refreshing the key set when it is missing,
// expired, or does not contain kid, within the refresh rate limit.
func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	if c.current != nil && c.now().Sub(c.current.fetchedAt) < c.ttl {
		if k, ok := c.current.keys[kid]; ok {
			c.mu.Unlock()
			return k, nil
		}
	}
	wait := c.startFetchLocked(ctx, false)
	c.mu.Unlock()

	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: waiting for key set refresh: %w", ErrJWKSUnavailable, ctx.Err())
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		if c.lastErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrJWKSUnavailable, c.lastErr)
		}
		return nil, fmt.Errorf("%w: no key set loaded yet", ErrJWKSUnavailable)
	}
	// Possibly stale: an expired set is still used when its refresh failed or is rate limited.
	if k, ok := c.current.keys[kid]; ok {
		return k, nil
	}
	if c.lastErr != nil {
		return nil, fmt.Errorf("%w: kid %s (last key set refresh failed: %w)", ErrUnknownKey, quote(kid), c.lastErr)
	}
	return nil, fmt.Errorf("%w: kid %s", ErrUnknownKey, quote(kid))
}

// refresh forces a fetch (joining one already in flight) and reports its outcome.
func (c *jwksCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	wait := c.startFetchLocked(ctx, true)
	c.mu.Unlock()
	select {
	case <-wait:
	case <-ctx.Done():
		return fmt.Errorf("%w: waiting for key set refresh: %w", ErrJWKSUnavailable, ctx.Err())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr != nil {
		return fmt.Errorf("%w: %w", ErrJWKSUnavailable, c.lastErr)
	}
	return nil
}

// startFetchLocked returns a channel closed when a fetch completes: the one in flight, or a new
// one if the rate limit allows (always when force is set). It returns nil when no fetch is
// allowed. c.mu must be held.
func (c *jwksCache) startFetchLocked(ctx context.Context, force bool) chan struct{} {
	if c.inflight != nil {
		return c.inflight
	}
	now := c.now()
	if !force && !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < c.minInterval {
		return nil
	}
	done := make(chan struct{})
	c.inflight = done
	c.lastAttempt = now
	// The fetch is shared by every waiting caller, so it must not be cancelled when the caller
	// that triggered it goes away; it keeps the caller's values and has its own timeout.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.fetchTimeout)
	go func() {
		defer cancel()
		set, err := c.fetch(fetchCtx)
		c.mu.Lock()
		if err != nil {
			c.lastErr = err
		} else {
			c.current, c.lastErr = set, nil
		}
		c.inflight = nil
		c.mu.Unlock()
		close(done)
	}()
	return done
}

// fetch downloads and parses the JWKS.
func (c *jwksCache) fetch(ctx context.Context) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/jwk-set+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: read body: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("fetch jwks: body exceeds %d bytes", maxJWKSBytes)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	return &keySet{keys: keys, fetchedAt: c.now()}, nil
}

// jwk is the subset of RFC 7517/7518 RSA key members AegisFlow uses.
type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"`
	E      string   `json:"e"`
}

// parseJWKS extracts the usable RS256 signature-verification keys of a JWK Set. Entries that are
// not RSA signing keys, are malformed, too small, or bound to another algorithm are skipped; a
// kid that maps to two different keys is dropped as ambiguous. A set without any usable key is
// an error, so a broken response never replaces the last good set.
func parseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	if len(doc.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("jwks has %d keys, limit is %d", len(doc.Keys), maxJWKSKeys)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	ambiguous := make(map[string]bool)
	for _, raw := range doc.Keys {
		var k jwk
		if err := json.Unmarshal(raw, &k); err != nil {
			continue
		}
		pub, err := k.rsaPublicKey()
		if err != nil {
			continue
		}
		if prev, dup := keys[k.Kid]; dup && !prev.Equal(pub) {
			ambiguous[k.Kid] = true
		}
		keys[k.Kid] = pub
	}
	for kid := range ambiguous {
		delete(keys, kid)
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contains no usable RS256 signing key")
	}
	return keys, nil
}

// rsaPublicKey validates the JWK and converts it to an RSA public key.
func (k *jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	switch {
	case k.Kty != "RSA":
		return nil, fmt.Errorf("kty %s is not RSA", quote(k.Kty))
	case k.Kid == "" || len(k.Kid) > maxKIDLen:
		return nil, errors.New("missing or oversized kid")
	case k.Use != "" && k.Use != "sig":
		return nil, fmt.Errorf("use %s is not sig", quote(k.Use))
	case k.Alg != "" && k.Alg != algRS256:
		return nil, fmt.Errorf("alg %s is not RS256", quote(k.Alg))
	case len(k.KeyOps) > 0 && !slices.Contains(k.KeyOps, "verify"):
		return nil, errors.New("key_ops does not allow verify")
	}
	nb, err := decodeKeyParam(k.N)
	if err != nil {
		return nil, fmt.Errorf("n: %w", err)
	}
	eb, err := decodeKeyParam(k.E)
	if err != nil {
		return nil, fmt.Errorf("e: %w", err)
	}
	n := new(big.Int).SetBytes(nb)
	if bits := n.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, fmt.Errorf("modulus is %d bits, want %d-%d", bits, minRSABits, maxRSABits)
	}
	if n.Bit(0) == 0 {
		return nil, errors.New("modulus is even")
	}
	if len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("exponent must be 1-4 bytes")
	}
	var e int64
	for _, b := range eb {
		e = e<<8 | int64(b)
	}
	if e < 3 || e > 1<<31-1 || e%2 == 0 {
		return nil, fmt.Errorf("exponent %d is not an odd value in [3, 2^31-1]", e)
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// decodeKeyParam decodes a base64url JWK parameter. Padding is tolerated here (the JWKS comes
// from the configured issuer over TLS); tokens themselves are decoded strictly.
func decodeKeyParam(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, errors.New("empty")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return b, nil
}
