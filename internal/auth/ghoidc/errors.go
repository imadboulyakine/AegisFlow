package ghoidc

import "errors"

// Sentinel errors returned (wrapped, with detail) by NewVerifier, Verify and the Claims helpers.
// Match them with errors.Is; the wrapped message is for logs, never for HTTP clients.
var (
	// ErrInvalidConfig reports a Config that NewVerifier refuses.
	ErrInvalidConfig = errors.New("ghoidc: invalid configuration")

	// ErrMalformed reports a token that is not a well-formed compact JWS/JWT: size, segment count,
	// base64url, JSON syntax, duplicate keys, claim types or critical header parameters.
	ErrMalformed = errors.New("ghoidc: malformed token")
	// ErrUnsupportedAlg reports a header `alg` other than RS256 (including none and HMAC).
	ErrUnsupportedAlg = errors.New("ghoidc: unsupported signing algorithm")
	// ErrUnknownKey reports a `kid` that is not in the issuer's key set, even after a refresh.
	ErrUnknownKey = errors.New("ghoidc: unknown signing key")
	// ErrSignature reports a signature that does not verify with the selected key.
	ErrSignature = errors.New("ghoidc: invalid signature")
	// ErrJWKSUnavailable reports that no usable key set could be obtained from the issuer.
	ErrJWKSUnavailable = errors.New("ghoidc: signing key set unavailable")

	// ErrIssuer reports an `iss` claim different from the configured issuer.
	ErrIssuer = errors.New("ghoidc: issuer not accepted")
	// ErrAudience reports an `aud` claim that does not contain the configured audience.
	ErrAudience = errors.New("ghoidc: audience not accepted")
	// ErrExpired reports a token whose `exp` is in the past (beyond the clock skew).
	ErrExpired = errors.New("ghoidc: token expired")
	// ErrNotYetValid reports a token whose `nbf` or `iat` is in the future (beyond the clock skew).
	ErrNotYetValid = errors.New("ghoidc: token not yet valid")
	// ErrMissingClaim reports that a claim AegisFlow requires is absent or empty.
	ErrMissingClaim = errors.New("ghoidc: required claim missing")

	// ErrForbidden matches every authorization failure: the token is authentic but the workflow
	// identity is outside the configured allow-lists. The specific errors below also match it.
	ErrForbidden = errors.New("ghoidc: workflow identity not authorized")
	// ErrRepositoryNotAllowed reports a `repository_id` or `repository_owner_id` outside the
	// allow-lists. It also matches ErrForbidden.
	ErrRepositoryNotAllowed error = &forbiddenError{msg: "ghoidc: repository not allowed"}
	// ErrRefNotAllowed reports a `ref` outside the ref allow-list. It also matches ErrForbidden.
	ErrRefNotAllowed error = &forbiddenError{msg: "ghoidc: ref not allowed"}
	// ErrEnvironmentNotAllowed reports an `environment` outside the environment allow-list.
	// It also matches ErrForbidden.
	ErrEnvironmentNotAllowed error = &forbiddenError{msg: "ghoidc: environment not allowed"}
	// ErrCommitMismatch reports evidence whose commit SHA differs from the token's `sha` claim
	// (see Claims.CheckCommit). It also matches ErrForbidden.
	ErrCommitMismatch error = &forbiddenError{msg: "ghoidc: commit does not match token sha"}
)

// forbiddenError is an authorization sentinel that also matches ErrForbidden, so callers can
// branch on the class (HTTP 403) or on the specific reason.
type forbiddenError struct{ msg string }

func (e *forbiddenError) Error() string { return e.msg }

// Is reports whether target is the ErrForbidden class sentinel.
func (e *forbiddenError) Is(target error) bool { return target == ErrForbidden }
