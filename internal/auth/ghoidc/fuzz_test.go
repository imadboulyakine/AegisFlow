package ghoidc

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// offlineTransport fails every request: fuzzed verifiers must never touch the network.
type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in fuzzing")
}

// fuzzVerifier returns a Verifier whose key cache is pre-loaded with testKey(0) and whose clock
// is frozen, so the rate limit prevents any fetch.
func fuzzVerifier(f *testing.F) *Verifier {
	f.Helper()
	v, err := NewVerifier(Config{
		Audience:             testAudience,
		JWKSURL:              "http://127.0.0.1:1/jwks",
		AllowedRepositoryIDs: []int64{testRepoID},
		AllowedOwnerIDs:      []int64{testOwnerID},
		HTTPClient:           &http.Client{Transport: offlineTransport{}},
	})
	if err != nil {
		f.Fatal(err)
	}
	v.now = func() time.Time { return testNow }
	v.keys.current = &keySet{keys: map[string]*rsa.PublicKey{testKID: &testKey(f, 0).PublicKey}, fetchedAt: testNow}
	v.keys.lastAttempt = testNow
	return v
}

func FuzzVerify(f *testing.F) {
	v := fuzzVerifier(f)
	valid := mint(f, testKey(f, 0), nil, nil)
	f.Add(valid)
	f.Add(mint(f, testKey(f, 1), nil, nil))
	f.Add(mint(f, testKey(f, 0), func(h map[string]any) { h["alg"] = "none" }, nil))
	f.Add(mint(f, testKey(f, 0), nil, func(c map[string]any) { c["repository_id"] = "75" }))
	f.Add(strings.Replace(valid, ".", "..", 1))
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIn0.e30.")
	f.Add("")
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, token string) {
		c, err := v.Verify(context.Background(), token)
		if err != nil {
			if c != nil {
				t.Fatalf("claims returned with error %v", err)
			}
			if reasonOf(err) == "invalid_token" {
				t.Fatalf("error %v matches no sentinel", err)
			}
			return
		}
		// Only genuinely signed tokens can succeed, and they must satisfy every policy.
		if c.RepositoryID != "74" || c.RepositoryOwnerID != "65" || c.Issuer != DefaultIssuer {
			t.Fatalf("accepted unexpected claims %+v", c)
		}
	})
}

func FuzzParseClaims(f *testing.F) {
	f.Add(mustJSON(f, defaultClaims()))
	f.Add([]byte(`{"aud":["a",1],"exp":1e400}`))
	f.Add([]byte(`{"exp":-1,"iat":"1","aud":null}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte("{\"sub\":\"\xff\"}"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		c, err := parseClaims(payload)
		if err != nil {
			if !errors.Is(err, ErrMalformed) || c != nil {
				t.Fatalf("parseClaims error %v (claims %v)", err, c)
			}
			return
		}
		if !c.ExpiresAt.IsZero() && (c.ExpiresAt.Unix() < 0 || c.ExpiresAt.Unix() > maxNumericDate) {
			t.Fatalf("exp out of range: %s", c.ExpiresAt)
		}
	})
}

func FuzzParseJWKS(f *testing.F) {
	f.Add(jwksDoc(map[string]*rsa.PublicKey{"a": &testKey(f, 0).PublicKey, "b": &testKey(f, 1).PublicKey}))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":[null,1,"x",{}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		keys, err := parseJWKS(body)
		if err != nil {
			return
		}
		if len(keys) == 0 {
			t.Fatal("no error but no keys")
		}
		for kid, k := range keys {
			if kid == "" || k.N.BitLen() < minRSABits || k.N.BitLen() > maxRSABits || k.E < 3 || k.E%2 == 0 {
				t.Fatalf("unsafe key %q accepted: %d bits, e=%d", kid, k.N.BitLen(), k.E)
			}
		}
	})
}

func FuzzParseSubject(f *testing.F) {
	for _, s := range []string{
		"repo:octo-org/octo-repo:ref:refs/heads/main",
		"repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main",
		"repo:o/r:pull_request",
		"environment:production%3Aeastus:repository_owner:octo-org",
		"repo:@/:",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sub string) {
		s, err := ParseSubject(sub)
		if err != nil {
			return
		}
		if len(s.Fields) == 0 || len(s.Fields) > maxSubjectSegments {
			t.Fatalf("ParseSubject(%q) produced %d fields", sub, len(s.Fields))
		}
		if s.Immutable && (s.OwnerID == "" || s.RepositoryID == "") {
			t.Fatalf("immutable subject without IDs: %+v", s)
		}
	})
}
