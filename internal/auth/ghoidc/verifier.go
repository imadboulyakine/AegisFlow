package ghoidc

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// Verifier verifies GitHub Actions OIDC tokens against one Config. It is safe for concurrent use.
type Verifier struct {
	issuer       string
	audience     string
	skew         time.Duration
	repoIDs      map[int64]struct{}
	ownerIDs     map[int64]struct{}
	refs         map[string]struct{}
	environments map[string]struct{}
	keys         *jwksCache
	now          func() time.Time
}

// NewVerifier validates cfg, applies defaults and returns a Verifier. It performs no network
// I/O; call Refresh to pre-load the key set at startup if desired.
func NewVerifier(cfg Config) (*Verifier, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	v := &Verifier{
		issuer:       cfg.Issuer,
		audience:     cfg.Audience,
		skew:         cfg.ClockSkew,
		repoIDs:      setOf(cfg.AllowedRepositoryIDs),
		ownerIDs:     setOf(cfg.AllowedOwnerIDs),
		refs:         setOf(cfg.AllowedRefs),
		environments: setOf(cfg.AllowedEnvironments),
		now:          time.Now,
	}
	v.keys = newJWKSCache(cfg, func() time.Time { return v.now() })
	return v, nil
}

func setOf[T comparable](items []T) map[T]struct{} {
	m := make(map[T]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

// Verify checks rawToken (the compact JWT, without any "Bearer " prefix) and returns its claims.
// The error wraps one of the package's sentinel errors; Claims are nil on error.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	tok, err := parseCompact(rawToken)
	if err != nil {
		return nil, err
	}
	key, err := v.keys.key(ctx, tok.kid)
	if err != nil {
		return nil, err
	}
	if err := verifyRS256(key, tok.signingInput, tok.signature); err != nil {
		return nil, err
	}
	claims, err := parseClaims(tok.payload)
	if err != nil {
		return nil, err
	}
	if err := v.checkClaims(claims, v.now()); err != nil {
		return nil, err
	}
	return claims, nil
}

// Refresh fetches the key set now (joining a fetch already in flight), bypassing the refresh
// rate limit. Use it to warm the cache at startup; a failure keeps any previous key set.
func (v *Verifier) Refresh(ctx context.Context) error {
	return v.keys.refresh(ctx)
}

// checkClaims validates the registered claims, then authorizes the workflow identity.
func (v *Verifier) checkClaims(c *Claims, now time.Time) error {
	if c.Issuer != v.issuer {
		return fmt.Errorf("%w: got %s", ErrIssuer, quote(c.Issuer))
	}
	if !slices.Contains(c.Audience, v.audience) {
		return fmt.Errorf("%w: %d audience value(s), none is ours", ErrAudience, len(c.Audience))
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("%w: iat", ErrMissingClaim)
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return fmt.Errorf("%w: exp is not after iat", ErrMalformed)
	}
	if !now.Before(c.ExpiresAt.Add(v.skew)) {
		return fmt.Errorf("%w: expired at %s", ErrExpired, c.ExpiresAt.Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() && now.Add(v.skew).Before(c.NotBefore) {
		return fmt.Errorf("%w: nbf is %s", ErrNotYetValid, c.NotBefore.Format(time.RFC3339))
	}
	if now.Add(v.skew).Before(c.IssuedAt) {
		return fmt.Errorf("%w: iat is %s", ErrNotYetValid, c.IssuedAt.Format(time.RFC3339))
	}
	for _, req := range []struct{ name, value string }{
		{"sub", c.Subject},
		{"repository", c.Repository},
		{"repository_id", c.RepositoryID},
		{"repository_owner", c.RepositoryOwner},
		{"repository_owner_id", c.RepositoryOwnerID},
		{"sha", c.SHA},
		{"run_id", c.RunID},
	} {
		if req.value == "" {
			return fmt.Errorf("%w: %s", ErrMissingClaim, req.name)
		}
	}

	// Authorization: numeric IDs only. Names can be renamed, transferred or re-registered by
	// someone else after deletion; IDs cannot.
	repoID, ok := parseID(c.RepositoryID)
	if !ok {
		return fmt.Errorf("%w: repository_id %s is not a canonical numeric ID", ErrMalformed, quote(c.RepositoryID))
	}
	ownerID, ok := parseID(c.RepositoryOwnerID)
	if !ok {
		return fmt.Errorf("%w: repository_owner_id %s is not a canonical numeric ID", ErrMalformed, quote(c.RepositoryOwnerID))
	}
	if len(v.repoIDs) > 0 {
		if _, ok := v.repoIDs[repoID]; !ok {
			return fmt.Errorf("%w: repository_id %d (%s)", ErrRepositoryNotAllowed, repoID, quote(c.Repository))
		}
	}
	if len(v.ownerIDs) > 0 {
		if _, ok := v.ownerIDs[ownerID]; !ok {
			return fmt.Errorf("%w: repository_owner_id %d (%s)", ErrRepositoryNotAllowed, ownerID, quote(c.RepositoryOwner))
		}
	}
	if len(v.refs) > 0 {
		if _, ok := v.refs[c.Ref]; !ok {
			return fmt.Errorf("%w: %s", ErrRefNotAllowed, quote(c.Ref))
		}
	}
	if len(v.environments) > 0 {
		if _, ok := v.environments[c.Environment]; !ok {
			return fmt.Errorf("%w: %s", ErrEnvironmentNotAllowed, quote(c.Environment))
		}
	}
	return nil
}
