package ghoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test fixtures. Keys are generated at test time; nothing secret-looking is committed.
var testNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

const (
	testAudience = "aegisflow-test"
	testRepoID   = 74
	testOwnerID  = 65
	testKID      = "kid-1"
)

var testSHA = strings.Repeat("a1b2c3d4e5", 4)

var generateTestKeys = sync.OnceValues(func() ([]*rsa.PrivateKey, error) {
	keys := make([]*rsa.PrivateKey, 3)
	for i := range keys {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keys[i] = k
	}
	return keys, nil
})

// testKey returns one of three RSA-2048 keys shared by the whole test binary.
func testKey(tb testing.TB, i int) *rsa.PrivateKey {
	tb.Helper()
	keys, err := generateTestKeys()
	if err != nil {
		tb.Fatalf("generate keys: %v", err)
	}
	return keys[i]
}

// gen carries the running subtest into token-building closures stored in test tables. The
// closures take gen rather than *testing.T because they are table data, not test helpers.
type gen struct{ t *testing.T }

// fakeClock is a manually advanced clock shared by a Verifier and its key cache.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// testJWK is the wire form of an RSA verification key.
type testJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func jwkOf(kid string, pub *rsa.PublicKey) testJWK {
	return testJWK{Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: b64(pub.N.Bytes()), E: b64(big.NewInt(int64(pub.E)).Bytes())}
}

// jwksDoc renders a JWK Set for the given keys, in kid order.
func jwksDoc(keys map[string]*rsa.PublicKey) []byte {
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	doc := struct {
		Keys []testJWK `json:"keys"`
	}{Keys: []testJWK{}}
	for _, kid := range kids {
		doc.Keys = append(doc.Keys, jwkOf(kid, keys[kid]))
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err) // unreachable: plain strings
	}
	return b
}

// jwksServer is an httptest issuer endpoint whose response can be changed and gated.
type jwksServer struct {
	*httptest.Server
	hits    atomic.Int64
	entered chan struct{} // receives once per request when non-nil (buffered)

	mu     sync.Mutex
	body   []byte
	status int
	gate   chan struct{} // when non-nil, requests block until it is closed
}

func newJWKSServer(t *testing.T, keys map[string]*rsa.PublicKey) *jwksServer {
	t.Helper()
	s := &jwksServer{body: jwksDoc(keys), status: http.StatusOK}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(func() {
		s.release()
		s.Close()
	})
	return s
}

func (s *jwksServer) serve(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	s.mu.Lock()
	gate, entered, body, status := s.gate, s.entered, s.body, s.status
	s.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *jwksServer) setKeys(keys map[string]*rsa.PublicKey) { s.set(jwksDoc(keys), http.StatusOK) }

func (s *jwksServer) set(body []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.status = body, status
}

// hold makes subsequent requests block until release; entered signals each request arrival.
func (s *jwksServer) hold() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gate = make(chan struct{})
	s.entered = make(chan struct{}, 64)
}

func (s *jwksServer) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gate != nil {
		close(s.gate)
		s.gate = nil
	}
}

// testEnv is a Verifier wired to a jwksServer serving testKey(0) as testKID.
type testEnv struct {
	srv   *jwksServer
	clock *fakeClock
	v     *Verifier
	cfg   Config
}

func baseConfig(srv *jwksServer) Config {
	return Config{
		Audience:             testAudience,
		JWKSURL:              srv.URL + "/.well-known/jwks",
		AllowedRepositoryIDs: []int64{testRepoID},
		AllowedOwnerIDs:      []int64{testOwnerID},
		HTTPClient:           srv.Client(),
	}
}

func newTestEnv(t *testing.T, mutate func(*Config)) *testEnv {
	t.Helper()
	srv := newJWKSServer(t, map[string]*rsa.PublicKey{testKID: &testKey(t, 0).PublicKey})
	cfg := baseConfig(srv)
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	clock := &fakeClock{t: testNow}
	v.now = clock.Now
	return &testEnv{srv: srv, clock: clock, v: v, cfg: cfg}
}

func defaultHeader() map[string]any {
	return map[string]any{"alg": "RS256", "typ": "JWT", "kid": testKID, "x5t": "test-thumbprint"}
}

func defaultClaims() map[string]any {
	return map[string]any{
		"iss":                   DefaultIssuer,
		"aud":                   testAudience,
		"sub":                   "repo:octo-org/octo-repo:ref:refs/heads/main",
		"jti":                   "test-jti",
		"ref":                   "refs/heads/main",
		"ref_type":              "branch",
		"sha":                   testSHA,
		"repository":            "octo-org/octo-repo",
		"repository_id":         "74",
		"repository_owner":      "octo-org",
		"repository_owner_id":   "65",
		"repository_visibility": "private",
		"run_id":                "9876543210",
		"run_number":            "10",
		"run_attempt":           "1",
		"runner_environment":    "github-hosted",
		"actor":                 "octocat",
		"actor_id":              "12",
		"workflow":              "CI",
		"workflow_ref":          "octo-org/octo-repo/.github/workflows/ci.yml@refs/heads/main",
		"job_workflow_ref":      "octo-org/octo-repo/.github/workflows/ci.yml@refs/heads/main",
		"event_name":            "push",
		"nbf":                   testNow.Add(-5 * time.Minute).Unix(),
		"iat":                   testNow.Add(-1 * time.Minute).Unix(),
		"exp":                   testNow.Add(4 * time.Minute).Unix(),
	}
}

func mustJSON(tb testing.TB, v any) []byte {
	tb.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	return b
}

// signRaw builds a compact JWS from raw header and payload JSON, signed RS256 with key.
func signRaw(tb testing.TB, key *rsa.PrivateKey, header, payload []byte) string {
	tb.Helper()
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}
	return input + "." + b64(sig)
}

// mint signs a token with key after letting the caller adjust the default header and claims.
func mint(tb testing.TB, key *rsa.PrivateKey, editHeader, editClaims func(map[string]any)) string {
	tb.Helper()
	h, c := defaultHeader(), defaultClaims()
	if editHeader != nil {
		editHeader(h)
	}
	if editClaims != nil {
		editClaims(c)
	}
	return signRaw(tb, key, mustJSON(tb, h), mustJSON(tb, c))
}

// withMember prepends a raw JSON member to a marshalled object: `{"a":1}` -> `{<member>,"a":1}`.
func withMember(obj []byte, member string) []byte {
	return []byte("{" + member + "," + string(obj[1:]))
}
