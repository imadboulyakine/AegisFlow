package ghoidc

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyAccepts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cfg        func(*Config)
		editHeader func(map[string]any)
		editClaims func(map[string]any)
		raw        func(gen) string // overrides header/claims editing
	}{
		{name: "default github token"},
		{name: "audience array containing ours", editClaims: func(c map[string]any) { c["aud"] = []string{"other", testAudience} }},
		{name: "expired within skew", editClaims: func(c map[string]any) {
			c["iat"] = testNow.Add(-6 * time.Minute).Unix()
			c["exp"] = testNow.Add(-30 * time.Second).Unix()
		}},
		{name: "nbf within skew", editClaims: func(c map[string]any) { c["nbf"] = testNow.Add(30 * time.Second).Unix() }},
		{name: "iat within skew", editClaims: func(c map[string]any) { c["iat"] = testNow.Add(30 * time.Second).Unix() }},
		{name: "no nbf", editClaims: func(c map[string]any) { delete(c, "nbf") }},
		{name: "fractional dates", editClaims: func(c map[string]any) {
			c["iat"] = float64(testNow.Unix()) - 0.5
			c["exp"] = float64(testNow.Unix()) + 120.25
		}},
		{name: "no typ", editHeader: func(h map[string]any) { delete(h, "typ") }},
		{name: "lowercase typ", editHeader: func(h map[string]any) { h["typ"] = "jwt" }},
		{name: "unknown header and claims ignored", editHeader: func(h map[string]any) { h["x5t#S256"] = "ignored" },
			editClaims: func(c map[string]any) {
				c["repo_property_team"] = "platform"
				c["nested"] = map[string]any{"a": []any{1, "b", nil}}
			}},
		{name: "null optional claims", editClaims: func(c map[string]any) { c["environment"] = nil; c["nbf"] = nil }},
		{name: "owner allow-list only", cfg: func(c *Config) { c.AllowedRepositoryIDs = nil }},
		{name: "repository allow-list only", cfg: func(c *Config) { c.AllowedOwnerIDs = nil }},
		{name: "ref allow-list", cfg: func(c *Config) { c.AllowedRefs = []string{"refs/heads/main", "refs/tags/v1.0.0"} }},
		{name: "environment allow-list", cfg: func(c *Config) { c.AllowedEnvironments = []string{"prod"} },
			editClaims: func(c map[string]any) { c["environment"] = "prod" }},
		{name: "immutable subject format", editClaims: func(c map[string]any) {
			c["sub"] = "repo:octo-org@65/octo-repo@74:ref:refs/heads/main"
		}},
		{name: "unparseable subject is not an error", editClaims: func(c map[string]any) { c["sub"] = "::weird::" }},
		{name: "json with whitespace", raw: func(g gen) string {
			h := []byte(" {\n \"alg\" : \"RS256\" ,\t\"kid\":\"" + testKID + "\" } ")
			c, err := json.MarshalIndent(defaultClaims(), " ", "\t")
			if err != nil {
				g.t.Fatal(err)
			}
			return signRaw(g.t, testKey(g.t, 0), h, c)
		}},
		{name: "large token under the limit", editClaims: func(c map[string]any) {
			c["padding"] = strings.Repeat("x", 10<<10)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t, tt.cfg)
			var tok string
			if tt.raw != nil {
				tok = tt.raw(gen{t})
			} else {
				tok = mint(t, testKey(t, 0), tt.editHeader, tt.editClaims)
			}
			c, err := env.v.Verify(context.Background(), tok)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if c.RepositoryID != "74" || c.RepositoryOwnerID != "65" || c.SHA != testSHA || c.Issuer != DefaultIssuer {
				t.Errorf("unexpected claims: %+v", c)
			}
		})
	}
}

func TestVerifyClaimsMapping(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, nil)
	tok := mint(t, testKey(t, 0), nil, func(c map[string]any) {
		c["environment"] = "prod"
		c["check_run_id"] = "555"
		c["workflow_sha"] = testSHA
		c["head_ref"] = "feature"
		c["base_ref"] = "main"
		c["enterprise"] = "avocado-corp"
		c["enterprise_id"] = "2"
	})
	c, err := env.v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	checks := map[string][2]string{
		"sub":                {c.Subject, "repo:octo-org/octo-repo:ref:refs/heads/main"},
		"jti":                {c.JWTID, "test-jti"},
		"repository":         {c.Repository, "octo-org/octo-repo"},
		"repository_owner":   {c.RepositoryOwner, "octo-org"},
		"visibility":         {c.RepositoryVisibility, "private"},
		"ref":                {c.Ref, "refs/heads/main"},
		"ref_type":           {c.RefType, "branch"},
		"run_id":             {c.RunID, "9876543210"},
		"run_number":         {c.RunNumber, "10"},
		"run_attempt":        {c.RunAttempt, "1"},
		"check_run_id":       {c.CheckRunID, "555"},
		"workflow":           {c.Workflow, "CI"},
		"workflow_ref":       {c.WorkflowRef, "octo-org/octo-repo/.github/workflows/ci.yml@refs/heads/main"},
		"workflow_sha":       {c.WorkflowSHA, testSHA},
		"job_workflow_ref":   {c.JobWorkflowRef, "octo-org/octo-repo/.github/workflows/ci.yml@refs/heads/main"},
		"event_name":         {c.EventName, "push"},
		"head_ref":           {c.HeadRef, "feature"},
		"base_ref":           {c.BaseRef, "main"},
		"environment":        {c.Environment, "prod"},
		"actor":              {c.Actor, "octocat"},
		"actor_id":           {c.ActorID, "12"},
		"runner_environment": {c.RunnerEnvironment, "github-hosted"},
		"enterprise":         {c.Enterprise, "avocado-corp"},
		"enterprise_id":      {c.EnterpriseID, "2"},
	}
	for name, got := range checks {
		if got[0] != got[1] {
			t.Errorf("%s = %q, want %q", name, got[0], got[1])
		}
	}
	if len(c.Audience) != 1 || c.Audience[0] != testAudience {
		t.Errorf("aud = %v", c.Audience)
	}
	if !c.ExpiresAt.Equal(testNow.Add(4*time.Minute)) || !c.IssuedAt.Equal(testNow.Add(-time.Minute)) ||
		!c.NotBefore.Equal(testNow.Add(-5*time.Minute)) {
		t.Errorf("dates: exp=%s iat=%s nbf=%s", c.ExpiresAt, c.IssuedAt, c.NotBefore)
	}
}

// hmacToken forges an HS256 token using secret as the MAC key (the classic RS/HS confusion
// attack uses the issuer's public key as the secret).
func hmacToken(t *testing.T, alg string, h crypto.Hash, secret []byte) string {
	t.Helper()
	hdr := defaultHeader()
	hdr["alg"] = alg
	input := b64(mustJSON(t, hdr)) + "." + b64(mustJSON(t, defaultClaims()))
	mac := hmac.New(h.New, secret)
	mac.Write([]byte(input))
	return input + "." + b64(mac.Sum(nil))
}

func TestVerifyRejects(t *testing.T) {
	t.Parallel()
	pub := &testKey(t, 0).PublicKey
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	valid := func(g gen) string { return mint(g.t, testKey(g.t, 0), nil, nil) }
	header := func(edit func(map[string]any)) func(g gen) string {
		return func(g gen) string { return mint(g.t, testKey(g.t, 0), edit, nil) }
	}
	claims := func(edit func(map[string]any)) func(g gen) string {
		return func(g gen) string { return mint(g.t, testKey(g.t, 0), nil, edit) }
	}
	rawHeader := func(h string) func(g gen) string {
		return func(g gen) string {
			return signRaw(g.t, testKey(g.t, 0), []byte(h), mustJSON(g.t, defaultClaims()))
		}
	}
	rawClaims := func(c []byte) func(g gen) string {
		return func(g gen) string { return signRaw(g.t, testKey(g.t, 0), mustJSON(g.t, defaultHeader()), c) }
	}
	claimsJSON := mustJSON(t, defaultClaims())
	segments := func(tok string) []string { return strings.Split(tok, ".") }

	tests := []struct {
		name    string
		cfg     func(*Config)
		token   func(gen) string
		wantErr error
	}{
		// Structure and encoding.
		{name: "empty", token: func(gen) string { return "" }, wantErr: ErrMalformed},
		{name: "one segment", token: func(gen) string { return "abc" }, wantErr: ErrMalformed},
		{name: "two segments", token: func(gen) string { return "abc.def" }, wantErr: ErrMalformed},
		{name: "four segments", token: func(g gen) string { return valid(g) + ".x" }, wantErr: ErrMalformed},
		{name: "JWE five segments", token: func(gen) string { return "a.b.c.d.e" }, wantErr: ErrMalformed},
		{name: "empty header segment", token: func(g gen) string { return "." + strings.SplitN(valid(g), ".", 2)[1] }, wantErr: ErrMalformed},
		{name: "empty payload segment", token: func(g gen) string {
			s := segments(valid(g))
			return s[0] + ".." + s[2]
		}, wantErr: ErrMalformed},
		{name: "missing signature", token: func(g gen) string {
			s := segments(valid(g))
			return s[0] + "." + s[1] + "."
		}, wantErr: ErrMalformed},
		{name: "oversized token", token: claims(func(c map[string]any) { c["padding"] = strings.Repeat("x", MaxTokenBytes) }), wantErr: ErrMalformed},
		{name: "oversized signature", token: func(g gen) string {
			s := segments(valid(g))
			return s[0] + "." + s[1] + "." + b64(make([]byte, maxSignatureBytes+1))
		}, wantErr: ErrMalformed},
		{name: "padded base64", token: func(g gen) string {
			s := segments(valid(g))
			return s[0] + "=." + s[1] + "." + s[2]
		}, wantErr: ErrMalformed},
		{name: "standard base64 alphabet", token: func(g gen) string {
			s := segments(valid(g))
			return s[0] + "." + s[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(s[2]) + "+/"
		}, wantErr: ErrMalformed},
		{name: "newline inside segment", token: func(g gen) string {
			s := segments(valid(g))
			return s[0][:4] + "\n" + s[0][4:] + "." + s[1] + "." + s[2]
		}, wantErr: ErrMalformed},
		{name: "bearer prefix left in token", token: func(g gen) string { return "Bearer " + valid(g) }, wantErr: ErrMalformed},

		// Header: algorithm allow-list and confusion attacks.
		{name: "alg none with empty signature", token: func(g gen) string {
			h := defaultHeader()
			h["alg"] = "none"
			return b64(mustJSON(g.t, h)) + "." + b64(claimsJSON) + "."
		}, wantErr: ErrUnsupportedAlg},
		{name: "alg None", token: header(func(h map[string]any) { h["alg"] = "None" }), wantErr: ErrUnsupportedAlg},
		{name: "alg NONE", token: header(func(h map[string]any) { h["alg"] = "NONE" }), wantErr: ErrUnsupportedAlg},
		{name: "HS256 with public key DER as secret", token: func(g gen) string {
			return hmacToken(g.t, "HS256", crypto.SHA256, der)
		}, wantErr: ErrUnsupportedAlg},
		{name: "HS256 with public key PEM as secret", token: func(g gen) string {
			return hmacToken(g.t, "HS256", crypto.SHA256, pemKey)
		}, wantErr: ErrUnsupportedAlg},
		{name: "HS384", token: func(g gen) string { return hmacToken(g.t, "HS384", crypto.SHA384, der) }, wantErr: ErrUnsupportedAlg},
		{name: "HS512", token: func(g gen) string { return hmacToken(g.t, "HS512", crypto.SHA512, der) }, wantErr: ErrUnsupportedAlg},
		{name: "ES256", token: header(func(h map[string]any) { h["alg"] = "ES256" }), wantErr: ErrUnsupportedAlg},
		{name: "PS256", token: header(func(h map[string]any) { h["alg"] = "PS256" }), wantErr: ErrUnsupportedAlg},
		{name: "RS512", token: header(func(h map[string]any) { h["alg"] = "RS512" }), wantErr: ErrUnsupportedAlg},
		{name: "EdDSA", token: header(func(h map[string]any) { h["alg"] = "EdDSA" }), wantErr: ErrUnsupportedAlg},
		{name: "lowercase rs256", token: header(func(h map[string]any) { h["alg"] = "rs256" }), wantErr: ErrUnsupportedAlg},
		{name: "alg with whitespace", token: header(func(h map[string]any) { h["alg"] = "RS256 " }), wantErr: ErrUnsupportedAlg},
		{name: "missing alg", token: header(func(h map[string]any) { delete(h, "alg") }), wantErr: ErrMalformed},
		{name: "null alg", token: header(func(h map[string]any) { h["alg"] = nil }), wantErr: ErrMalformed},
		{name: "numeric alg", token: header(func(h map[string]any) { h["alg"] = 256 }), wantErr: ErrMalformed},
		{name: "duplicate alg none last", token: rawHeader(`{"alg":"RS256","kid":"kid-1","alg":"none"}`), wantErr: ErrMalformed},
		{name: "duplicate alg RS256 last", token: rawHeader(`{"alg":"none","kid":"kid-1","alg":"RS256"}`), wantErr: ErrMalformed},
		{name: "duplicate alg hidden by escape", token: rawHeader(`{"alg":"RS256","kid":"kid-1","alg":"none"}`), wantErr: ErrMalformed},
		{name: "case variant ALG is not alg", token: rawHeader(`{"ALG":"RS256","kid":"kid-1"}`), wantErr: ErrMalformed},
		{name: "header is an array", token: rawHeader(`["RS256","kid-1"]`), wantErr: ErrMalformed},
		{name: "header trailing data", token: rawHeader(`{"alg":"RS256","kid":"kid-1"}{}`), wantErr: ErrMalformed},
		{name: "header invalid utf-8", token: rawHeader("{\"alg\":\"RS256\",\"kid\":\"kid-1\",\"x\":\"\xff\"}"), wantErr: ErrMalformed},
		{name: "header not json", token: rawHeader(`alg=RS256`), wantErr: ErrMalformed},
		{name: "crit header", token: header(func(h map[string]any) { h["crit"] = []string{"b64"}; h["b64"] = false }), wantErr: ErrMalformed},
		{name: "typ not JWT", token: header(func(h map[string]any) { h["typ"] = "at+jwt" }), wantErr: ErrMalformed},
		{name: "typ not string", token: header(func(h map[string]any) { h["typ"] = 1 }), wantErr: ErrMalformed},

		// Key selection.
		{name: "missing kid", token: header(func(h map[string]any) { delete(h, "kid") }), wantErr: ErrMalformed},
		{name: "empty kid", token: header(func(h map[string]any) { h["kid"] = "" }), wantErr: ErrMalformed},
		{name: "numeric kid", token: header(func(h map[string]any) { h["kid"] = 1 }), wantErr: ErrMalformed},
		{name: "oversized kid", token: header(func(h map[string]any) { h["kid"] = strings.Repeat("k", maxKIDLen+1) }), wantErr: ErrMalformed},
		{name: "unknown kid", token: func(g gen) string {
			return mint(g.t, testKey(g.t, 1), func(h map[string]any) { h["kid"] = "kid-2" }, nil)
		}, wantErr: ErrUnknownKey},
		{name: "kid swap: other key, trusted kid", token: func(g gen) string {
			return mint(g.t, testKey(g.t, 1), nil, nil)
		}, wantErr: ErrSignature},
		{name: "embedded jwk with attacker kid", token: func(g gen) string {
			return mint(g.t, testKey(g.t, 1), func(h map[string]any) {
				h["kid"] = "attacker"
				h["jwk"] = jwkOf("attacker", &testKey(g.t, 1).PublicKey)
			}, nil)
		}, wantErr: ErrUnknownKey},
		{name: "embedded jwk with trusted kid", token: func(g gen) string {
			return mint(g.t, testKey(g.t, 1), func(h map[string]any) { h["jwk"] = jwkOf(testKID, &testKey(g.t, 1).PublicKey) }, nil)
		}, wantErr: ErrSignature},

		// Signature.
		{name: "tampered payload", token: func(g gen) string {
			s := segments(valid(g))
			forged := defaultClaims()
			forged["repository_id"] = "75"
			return s[0] + "." + b64(mustJSON(g.t, forged)) + "." + s[2]
		}, wantErr: ErrSignature},
		{name: "tampered header", token: func(g gen) string {
			s := segments(valid(g))
			h := defaultHeader()
			h["x5t"] = "other"
			return b64(mustJSON(g.t, h)) + "." + s[1] + "." + s[2]
		}, wantErr: ErrSignature},
		{name: "flipped signature bit", token: func(g gen) string {
			s := segments(valid(g))
			sig, err := decodeSegment(s[2])
			if err != nil {
				g.t.Fatal(err)
			}
			sig[len(sig)/2] ^= 0x01
			return s[0] + "." + s[1] + "." + b64(sig)
		}, wantErr: ErrSignature},
		{name: "truncated signature", token: func(g gen) string {
			s := segments(valid(g))
			sig, err := decodeSegment(s[2])
			if err != nil {
				g.t.Fatal(err)
			}
			return s[0] + "." + s[1] + "." + b64(sig[:len(sig)-1])
		}, wantErr: ErrSignature},

		// Claim syntax ("weird JSON").
		{name: "duplicate aud", token: rawClaims(withMember(claimsJSON, `"aud":"evil"`)), wantErr: ErrMalformed},
		{name: "duplicate repository_id", token: rawClaims(withMember(claimsJSON, `"repository_id":"999"`)), wantErr: ErrMalformed},
		{name: "case variant AUD is not aud", token: claims(func(c map[string]any) { c["aud"] = "other"; c["AUD"] = testAudience }), wantErr: ErrAudience},
		{name: "case variant Repository_Id is not repository_id", token: claims(func(c map[string]any) {
			delete(c, "repository_id")
			c["Repository_Id"] = "74"
		}), wantErr: ErrMissingClaim},
		{name: "numeric repository_id", token: claims(func(c map[string]any) { c["repository_id"] = 74 }), wantErr: ErrMalformed},
		{name: "repository_id with leading zero", token: claims(func(c map[string]any) { c["repository_id"] = "074" }), wantErr: ErrMalformed},
		{name: "negative repository_id", token: claims(func(c map[string]any) { c["repository_id"] = "-74" }), wantErr: ErrMalformed},
		{name: "repository_id with space", token: claims(func(c map[string]any) { c["repository_id"] = "74 " }), wantErr: ErrMalformed},
		{name: "owner id not numeric", token: claims(func(c map[string]any) { c["repository_owner_id"] = "octo-org" }), wantErr: ErrMalformed},
		{name: "exp as string", token: claims(func(c map[string]any) { c["exp"] = "4102444800" }), wantErr: ErrMalformed},
		{name: "negative exp", token: claims(func(c map[string]any) { c["exp"] = -1 }), wantErr: ErrMalformed},
		{name: "huge exp", token: rawClaims(withMember(mustJSON(t, without(defaultClaims(), "exp")), `"exp":1e400`)), wantErr: ErrMalformed},
		{name: "exp beyond year 9999", token: claims(func(c map[string]any) { c["exp"] = int64(maxNumericDate) + 1 }), wantErr: ErrMalformed},
		{name: "aud as number", token: claims(func(c map[string]any) { c["aud"] = 1 }), wantErr: ErrMalformed},
		{name: "aud array with number", token: claims(func(c map[string]any) { c["aud"] = []any{testAudience, 1} }), wantErr: ErrMalformed},
		{name: "claims array", token: rawClaims([]byte(`[{"iss":"x"}]`)), wantErr: ErrMalformed},
		{name: "claims trailing data", token: rawClaims(append(append([]byte{}, claimsJSON...), []byte(`{"x":1}`)...)), wantErr: ErrMalformed},
		{name: "claims invalid utf-8", token: rawClaims(withMember(claimsJSON, "\"x\":\"\xc3\x28\"")), wantErr: ErrMalformed},
		{name: "claims truncated json", token: rawClaims(claimsJSON[:len(claimsJSON)-1]), wantErr: ErrMalformed},

		// Registered claims.
		{name: "wrong issuer", token: claims(func(c map[string]any) { c["iss"] = "https://token.actions.example.com" }), wantErr: ErrIssuer},
		{name: "issuer with trailing slash", token: claims(func(c map[string]any) { c["iss"] = DefaultIssuer + "/" }), wantErr: ErrIssuer},
		{name: "missing issuer", token: claims(func(c map[string]any) { delete(c, "iss") }), wantErr: ErrIssuer},
		{name: "wrong audience", token: claims(func(c map[string]any) { c["aud"] = "https://github.com/octo-org" }), wantErr: ErrAudience},
		{name: "audience array without ours", token: claims(func(c map[string]any) { c["aud"] = []string{"a", "b"} }), wantErr: ErrAudience},
		{name: "empty audience array", token: claims(func(c map[string]any) { c["aud"] = []string{} }), wantErr: ErrAudience},
		{name: "missing audience", token: claims(func(c map[string]any) { delete(c, "aud") }), wantErr: ErrAudience},
		{name: "audience case differs", token: claims(func(c map[string]any) { c["aud"] = strings.ToUpper(testAudience) }), wantErr: ErrAudience},
		{name: "expired beyond skew", token: claims(func(c map[string]any) {
			c["iat"] = testNow.Add(-10 * time.Minute).Unix()
			c["exp"] = testNow.Add(-61 * time.Second).Unix()
		}), wantErr: ErrExpired},
		{name: "expired exactly at skew", token: claims(func(c map[string]any) {
			c["iat"] = testNow.Add(-10 * time.Minute).Unix()
			c["exp"] = testNow.Add(-60 * time.Second).Unix()
		}), wantErr: ErrExpired},
		{name: "nbf beyond skew", token: claims(func(c map[string]any) { c["nbf"] = testNow.Add(2 * time.Minute).Unix() }), wantErr: ErrNotYetValid},
		{name: "iat in the future", token: claims(func(c map[string]any) {
			c["iat"] = testNow.Add(2 * time.Minute).Unix()
			c["exp"] = testNow.Add(7 * time.Minute).Unix()
		}), wantErr: ErrNotYetValid},
		{name: "missing exp", token: claims(func(c map[string]any) { delete(c, "exp") }), wantErr: ErrMissingClaim},
		{name: "missing iat", token: claims(func(c map[string]any) { delete(c, "iat") }), wantErr: ErrMissingClaim},
		{name: "exp before iat", token: claims(func(c map[string]any) { c["exp"] = testNow.Add(-2 * time.Minute).Unix() }), wantErr: ErrMalformed},
		{name: "missing sub", token: claims(func(c map[string]any) { delete(c, "sub") }), wantErr: ErrMissingClaim},
		{name: "missing repository", token: claims(func(c map[string]any) { delete(c, "repository") }), wantErr: ErrMissingClaim},
		{name: "missing repository_id", token: claims(func(c map[string]any) { delete(c, "repository_id") }), wantErr: ErrMissingClaim},
		{name: "missing repository_owner_id", token: claims(func(c map[string]any) { delete(c, "repository_owner_id") }), wantErr: ErrMissingClaim},
		{name: "missing sha", token: claims(func(c map[string]any) { delete(c, "sha") }), wantErr: ErrMissingClaim},
		{name: "empty run_id", token: claims(func(c map[string]any) { c["run_id"] = "" }), wantErr: ErrMissingClaim},

		// Authorization.
		{name: "repository id not allowed", token: claims(func(c map[string]any) { c["repository_id"] = "75" }), wantErr: ErrRepositoryNotAllowed},
		{name: "same name, different repository id", token: claims(func(c map[string]any) {
			c["repository_id"] = "123456789"
			c["sub"] = "repo:octo-org/octo-repo:ref:refs/heads/main"
		}), wantErr: ErrRepositoryNotAllowed},
		{name: "owner id not allowed", token: claims(func(c map[string]any) { c["repository_owner_id"] = "66" }), wantErr: ErrRepositoryNotAllowed},
		{name: "owner-only list rejects other owner", cfg: func(c *Config) { c.AllowedRepositoryIDs = nil },
			token: claims(func(c map[string]any) { c["repository_owner_id"] = "66" }), wantErr: ErrRepositoryNotAllowed},
		{name: "sub naming allowed repo does not authorize", token: claims(func(c map[string]any) {
			c["repository_id"] = "75"
			c["sub"] = "repo:octo-org@65/octo-repo@74:ref:refs/heads/main"
		}), wantErr: ErrRepositoryNotAllowed},
		{name: "ref not allowed", cfg: func(c *Config) { c.AllowedRefs = []string{"refs/heads/main"} },
			token: claims(func(c map[string]any) { c["ref"] = "refs/heads/feature" }), wantErr: ErrRefNotAllowed},
		{name: "ref missing with allow-list", cfg: func(c *Config) { c.AllowedRefs = []string{"refs/heads/main"} },
			token: claims(func(c map[string]any) { delete(c, "ref") }), wantErr: ErrRefNotAllowed},
		{name: "environment not allowed", cfg: func(c *Config) { c.AllowedEnvironments = []string{"prod"} },
			token: claims(func(c map[string]any) { c["environment"] = "staging" }), wantErr: ErrEnvironmentNotAllowed},
		{name: "environment missing with allow-list", cfg: func(c *Config) { c.AllowedEnvironments = []string{"prod"} },
			token: valid, wantErr: ErrEnvironmentNotAllowed},
		{name: "custom issuer rejects default issuer", cfg: func(c *Config) {
			c.Issuer = "https://token.actions.githubusercontent.com/avocado-corp"
		}, token: valid, wantErr: ErrIssuer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t, tt.cfg)
			c, err := env.v.Verify(context.Background(), tt.token(gen{t}))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify error = %v, want %v", err, tt.wantErr)
			}
			if c != nil {
				t.Errorf("claims returned with error: %+v", c)
			}
			if reasonOf(err) == "invalid_token" {
				t.Errorf("error %v matches no sentinel", err)
			}
			if errors.Is(tt.wantErr, ErrForbidden) != errors.Is(err, ErrForbidden) {
				t.Errorf("ErrForbidden class mismatch for %v", err)
			}
		})
	}
}

func without(m map[string]any, key string) map[string]any {
	delete(m, key)
	return m
}

// An attacker-supplied jku must never be fetched.
func TestVerifyIgnoresJKU(t *testing.T) {
	t.Parallel()
	var attackerHits atomic.Int64
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerHits.Add(1)
		_, _ = w.Write(jwksDoc(map[string]*rsa.PublicKey{"attacker": &testKey(t, 1).PublicKey}))
	}))
	t.Cleanup(attacker.Close)
	env := newTestEnv(t, nil)
	for _, h := range []string{"jku", "x5u"} {
		tok := mint(t, testKey(t, 1), func(m map[string]any) {
			m["kid"] = "attacker"
			m[h] = attacker.URL
		}, nil)
		if _, err := env.v.Verify(context.Background(), tok); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("%s: error = %v, want ErrUnknownKey", h, err)
		}
	}
	if n := attackerHits.Load(); n != 0 {
		t.Errorf("attacker key URL fetched %d times", n)
	}
}

func TestDecodeSegmentCanonical(t *testing.T) {
	t.Parallel()
	if b, err := decodeSegment("QQ"); err != nil || string(b) != "A" {
		t.Fatalf("decodeSegment(QQ) = %q, %v", b, err)
	}
	for _, s := range []string{"QR", "QQ==", "Q", "Q Q", "QQ\r", "Q+", "Q/"} {
		if _, err := decodeSegment(s); err == nil {
			t.Errorf("decodeSegment(%q) accepted a non-canonical encoding", s)
		}
	}
}

func TestClaimsCheckCommit(t *testing.T) {
	t.Parallel()
	c := &Claims{SHA: testSHA}
	sha256Hex := strings.Repeat("0f", 32)
	tests := []struct {
		name   string
		claims *Claims
		sha    string
		ok     bool
	}{
		{name: "equal", claims: c, sha: testSHA, ok: true},
		{name: "case-insensitive", claims: c, sha: strings.ToUpper(testSHA), ok: true},
		{name: "sha-256 object id", claims: &Claims{SHA: sha256Hex}, sha: sha256Hex, ok: true},
		{name: "different", claims: c, sha: strings.Repeat("b", 40)},
		{name: "prefix", claims: c, sha: testSHA[:12]},
		{name: "empty evidence sha", claims: c, sha: ""},
		{name: "empty token sha", claims: &Claims{}, sha: ""},
		{name: "non-hex", claims: &Claims{SHA: strings.Repeat("z", 40)}, sha: strings.Repeat("z", 40)},
		{name: "nil claims", claims: nil, sha: testSHA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.claims.CheckCommit(tt.sha)
			if tt.ok != (err == nil) {
				t.Fatalf("CheckCommit = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && (!errors.Is(err, ErrCommitMismatch) || !errors.Is(err, ErrForbidden)) {
				t.Errorf("error %v does not match ErrCommitMismatch and ErrForbidden", err)
			}
		})
	}
}

func TestErrorClasses(t *testing.T) {
	t.Parallel()
	for _, err := range []error{ErrRepositoryNotAllowed, ErrRefNotAllowed, ErrEnvironmentNotAllowed, ErrCommitMismatch} {
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("%v does not match ErrForbidden", err)
		}
		if errors.Is(err, ErrMalformed) {
			t.Errorf("%v matches ErrMalformed", err)
		}
	}
	if errors.Is(ErrRepositoryNotAllowed, ErrRefNotAllowed) {
		t.Error("distinct forbidden sentinels must not match each other")
	}
	if errors.Is(ErrMalformed, ErrForbidden) {
		t.Error("ErrMalformed must not match ErrForbidden")
	}
}
