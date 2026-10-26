package ghoidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustVerify(t *testing.T, env *testEnv, tok string) {
	t.Helper()
	if _, err := env.v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func wantHits(t *testing.T, env *testEnv, want int64) {
	t.Helper()
	if got := env.srv.hits.Load(); got != want {
		t.Fatalf("JWKS fetches = %d, want %d", got, want)
	}
}

func TestJWKSConcurrentCallersShareOneFetch(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	env.srv.hold()
	tok := mint(t, testKey(t, 0), nil, nil)

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			_, err := env.v.Verify(context.Background(), tok)
			errs <- err
		})
	}
	<-env.srv.entered // the single fetch reached the issuer and is blocked
	env.srv.release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Verify: %v", err)
		}
	}
	wantHits(t, env, 1)
}

func TestJWKSCacheTTL(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, func(c *Config) { c.JWKSCacheTTL = 10 * time.Minute })
	tok := mint(t, testKey(t, 0), nil, func(c map[string]any) { c["exp"] = testNow.Add(time.Hour).Unix() })

	mustVerify(t, env, tok)
	wantHits(t, env, 1)
	env.clock.Advance(9 * time.Minute)
	mustVerify(t, env, tok)
	wantHits(t, env, 1) // still fresh
	env.clock.Advance(2 * time.Minute)
	mustVerify(t, env, tok)
	wantHits(t, env, 2) // expired: refreshed before use
}

func TestJWKSUnknownKidRefreshIsRateLimited(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	mustVerify(t, env, mint(t, testKey(t, 0), nil, nil))
	wantHits(t, env, 1)

	// The issuer rotates in a new key.
	env.srv.setKeys(map[string]*rsa.PublicKey{testKID: &testKey(t, 0).PublicKey, "kid-2": &testKey(t, 1).PublicKey})
	rotated := mint(t, testKey(t, 1), func(h map[string]any) { h["kid"] = "kid-2" }, nil)

	env.clock.Advance(10 * time.Second)
	if _, err := env.v.Verify(context.Background(), rotated); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("within the refresh interval: error = %v, want ErrUnknownKey", err)
	}
	// A flood of random kids cannot make the verifier hammer the issuer.
	for i := range 200 {
		tok := mint(t, testKey(t, 2), func(h map[string]any) { h["kid"] = fmt.Sprintf("flood-%d", i) }, nil)
		if _, err := env.v.Verify(context.Background(), tok); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("flood token %d: error = %v, want ErrUnknownKey", i, err)
		}
	}
	wantHits(t, env, 1)

	env.clock.Advance(DefaultJWKSMinRefreshInterval)
	mustVerify(t, env, rotated) // interval elapsed: unknown kid triggers one refresh
	wantHits(t, env, 2)
	mustVerify(t, env, mint(t, testKey(t, 0), nil, nil)) // old key still served
	wantHits(t, env, 2)
}

func TestJWKSKeepsLastGoodSetOnFailure(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	tok := mint(t, testKey(t, 0), nil, func(c map[string]any) { c["exp"] = testNow.Add(3 * time.Hour).Unix() })
	mustVerify(t, env, tok)

	env.srv.set([]byte("upstream error"), http.StatusBadGateway)
	env.clock.Advance(DefaultJWKSCacheTTL + time.Second)
	mustVerify(t, env, tok) // refresh failed: last good set used
	wantHits(t, env, 2)
	mustVerify(t, env, tok) // failure is rate limited too
	wantHits(t, env, 2)

	env.srv.set([]byte(`{"keys":[{"kty":"EC","kid":"x"}]}`), http.StatusOK) // no usable key
	env.clock.Advance(DefaultJWKSMinRefreshInterval)
	mustVerify(t, env, tok)
	wantHits(t, env, 3)

	env.srv.set([]byte(`{"keys":`), http.StatusOK) // truncated JSON
	env.clock.Advance(DefaultJWKSMinRefreshInterval)
	mustVerify(t, env, tok)
	wantHits(t, env, 4)

	// The unknown-kid error explains that the last refresh failed.
	env.clock.Advance(DefaultJWKSMinRefreshInterval)
	other := mint(t, testKey(t, 1), func(h map[string]any) { h["kid"] = "kid-2" },
		func(c map[string]any) { c["exp"] = testNow.Add(3 * time.Hour).Unix() })
	if _, err := env.v.Verify(context.Background(), other); !errors.Is(err, ErrUnknownKey) ||
		!strings.Contains(err.Error(), "refresh failed") {
		t.Fatalf("error = %v, want ErrUnknownKey mentioning the failed refresh", err)
	}

	// Recovery: the issuer removed kid-1, which must then be refused.
	env.srv.setKeys(map[string]*rsa.PublicKey{"kid-2": &testKey(t, 1).PublicKey})
	env.clock.Advance(DefaultJWKSCacheTTL)
	if _, err := env.v.Verify(context.Background(), tok); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("revoked key: error = %v, want ErrUnknownKey", err)
	}
	mustVerify(t, env, other)
}

func TestJWKSUnavailableUntilFirstSuccess(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	env.srv.set(nil, http.StatusServiceUnavailable)
	tok := mint(t, testKey(t, 0), nil, nil)

	for range 3 {
		if _, err := env.v.Verify(context.Background(), tok); !errors.Is(err, ErrJWKSUnavailable) {
			t.Fatalf("error = %v, want ErrJWKSUnavailable", err)
		}
	}
	wantHits(t, env, 1) // rate limited after the first failure

	env.srv.setKeys(map[string]*rsa.PublicKey{testKID: &testKey(t, 0).PublicKey})
	env.clock.Advance(DefaultJWKSMinRefreshInterval)
	mustVerify(t, env, tok)
	wantHits(t, env, 2)
}

func TestJWKSCallerCancellationDoesNotAbortSharedFetch(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	env.srv.hold()
	tok := mint(t, testKey(t, 0), nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := env.v.Verify(ctx, tok)
		done <- err
	}()
	<-env.srv.entered
	cancel()
	err := <-done
	if !errors.Is(err, ErrJWKSUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want ErrJWKSUnavailable wrapping context.Canceled", err)
	}

	env.srv.release()
	// The fetch started by the cancelled caller completes and serves the next caller.
	mustVerify(t, env, tok)
	wantHits(t, env, 1)
}

func TestJWKSFetchTimeout(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	env.v.keys.fetchTimeout = 50 * time.Millisecond
	env.srv.hold()
	err := env.v.Refresh(context.Background())
	if !errors.Is(err, ErrJWKSUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Refresh error = %v, want ErrJWKSUnavailable wrapping DeadlineExceeded", err)
	}
}

func TestRefreshBypassesRateLimit(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	for i := range 3 {
		if err := env.v.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		wantHits(t, env, int64(i+1))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	env.srv.hold()
	if err := env.v.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh with cancelled context = %v", err)
	}
}

func TestJWKSFetchErrors(t *testing.T) {
	t.Parallel()
	redirect := httptest.NewServer(http.RedirectHandler("https://attacker.example/jwks", http.StatusFound))
	t.Cleanup(redirect.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	tests := []struct {
		name    string
		body    []byte
		status  int
		cfg     func(*Config)
		wantMsg string
	}{
		{name: "not found", status: http.StatusNotFound, wantMsg: "status 404"},
		{name: "body too large", status: http.StatusOK, body: []byte(`{"keys":[],"pad":"` + strings.Repeat("x", maxJWKSBytes) + `"}`), wantMsg: "exceeds"},
		{name: "invalid json", status: http.StatusOK, body: []byte(`<html>`), wantMsg: "decode jwks"},
		{name: "keys not an array", status: http.StatusOK, body: []byte(`{"keys":{}}`), wantMsg: "decode jwks"},
		{name: "no keys", status: http.StatusOK, body: []byte(`{"keys":[]}`), wantMsg: "no usable"},
		{name: "redirect not followed", cfg: func(c *Config) {
			c.JWKSURL = redirect.URL
			c.HTTPClient = nil // default client
		}, wantMsg: "status 302"},
		{name: "connection refused", cfg: func(c *Config) { c.JWKSURL = closed.URL }, wantMsg: "fetch jwks"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t, tt.cfg)
			if tt.status != 0 {
				env.srv.set(tt.body, tt.status)
			}
			err := env.v.Refresh(context.Background())
			if !errors.Is(err, ErrJWKSUnavailable) || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("Refresh error = %v, want ErrJWKSUnavailable containing %q", err, tt.wantMsg)
			}
		})
	}
}

func TestParseJWKS(t *testing.T) {
	t.Parallel()
	pub0, pub1 := &testKey(t, 0).PublicKey, &testKey(t, 1).PublicKey
	good := jwkOf("good", pub0)
	mod := func(edit func(*testJWK)) testJWK {
		k := jwkOf("k", pub1)
		edit(&k)
		return k
	}
	odd1024 := new(big.Int).Lsh(big.NewInt(1), 1023)
	odd1024.SetBit(odd1024, 0, 1)
	odd9000 := new(big.Int).Lsh(big.NewInt(1), 8999)
	odd9000.SetBit(odd9000, 0, 1)
	even := new(big.Int).Set(pub1.N)
	even.SetBit(even, 0, 0)

	tests := []struct {
		name     string
		entries  []any
		wantKids []string
		wantErr  bool
	}{
		{name: "single key", entries: []any{good}, wantKids: []string{"good"}},
		{name: "use and alg optional", entries: []any{mod(func(k *testJWK) { k.Use, k.Alg = "", "" })}, wantKids: []string{"k"}},
		{name: "padded parameters tolerated", entries: []any{mod(func(k *testJWK) { k.N += "=="; k.E += "=" })}, wantKids: []string{"k"}},
		{name: "key_ops with verify", entries: []any{map[string]any{"kty": "RSA", "kid": "k", "n": good.N, "e": good.E, "key_ops": []string{"verify"}}}, wantKids: []string{"k"}},
		{name: "key_ops without verify skipped", entries: []any{good, map[string]any{"kty": "RSA", "kid": "k", "n": good.N, "e": good.E, "key_ops": []string{"encrypt"}}}, wantKids: []string{"good"}},
		{name: "non-RSA skipped", entries: []any{good, map[string]any{"kty": "EC", "kid": "ec", "crv": "P-256"}}, wantKids: []string{"good"}},
		{name: "encryption key skipped", entries: []any{good, mod(func(k *testJWK) { k.Use = "enc" })}, wantKids: []string{"good"}},
		{name: "other alg skipped", entries: []any{good, mod(func(k *testJWK) { k.Alg = "RS512" })}, wantKids: []string{"good"}},
		{name: "missing kid skipped", entries: []any{good, mod(func(k *testJWK) { k.Kid = "" })}, wantKids: []string{"good"}},
		{name: "1024-bit key skipped", entries: []any{good, mod(func(k *testJWK) { k.N = b64(odd1024.Bytes()) })}, wantKids: []string{"good"}},
		{name: "oversized key skipped", entries: []any{good, mod(func(k *testJWK) { k.N = b64(odd9000.Bytes()) })}, wantKids: []string{"good"}},
		{name: "even modulus skipped", entries: []any{good, mod(func(k *testJWK) { k.N = b64(even.Bytes()) })}, wantKids: []string{"good"}},
		{name: "even exponent skipped", entries: []any{good, mod(func(k *testJWK) { k.E = b64([]byte{1, 0, 0}) })}, wantKids: []string{"good"}},
		{name: "exponent 1 skipped", entries: []any{good, mod(func(k *testJWK) { k.E = b64([]byte{1}) })}, wantKids: []string{"good"}},
		{name: "oversized exponent skipped", entries: []any{good, mod(func(k *testJWK) { k.E = b64([]byte{1, 0, 0, 0, 1}) })}, wantKids: []string{"good"}},
		{name: "bad base64 skipped", entries: []any{good, mod(func(k *testJWK) { k.N = "!!!" })}, wantKids: []string{"good"}},
		{name: "empty modulus skipped", entries: []any{good, mod(func(k *testJWK) { k.N = "" })}, wantKids: []string{"good"}},
		{name: "wrong member type skipped", entries: []any{good, map[string]any{"kty": "RSA", "kid": 7}}, wantKids: []string{"good"}},
		{name: "non-object entry skipped", entries: []any{good, "string", 1, nil}, wantKids: []string{"good"}},
		{name: "duplicate kid same key kept", entries: []any{good, good}, wantKids: []string{"good"}},
		{name: "ambiguous kid dropped", entries: []any{good, jwkOf("dup", pub0), jwkOf("dup", pub1)}, wantKids: []string{"good"}},
		{name: "only ambiguous kid is an error", entries: []any{jwkOf("dup", pub0), jwkOf("dup", pub1)}, wantErr: true},
		{name: "no usable key", entries: []any{map[string]any{"kty": "oct", "kid": "h", "k": "c2VjcmV0"}}, wantErr: true},
		{name: "too many keys", entries: func() []any {
			out := make([]any, maxJWKSKeys+1)
			for i := range out {
				out[i] = good
			}
			return out
		}(), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body, err := json.Marshal(map[string]any{"keys": tt.entries})
			if err != nil {
				t.Fatal(err)
			}
			keys, err := parseJWKS(body)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseJWKS accepted %s", body)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseJWKS: %v", err)
			}
			if len(keys) != len(tt.wantKids) {
				t.Fatalf("got %d keys, want %v", len(keys), tt.wantKids)
			}
			for _, kid := range tt.wantKids {
				if keys[kid] == nil {
					t.Errorf("kid %q missing", kid)
				}
			}
		})
	}
}
