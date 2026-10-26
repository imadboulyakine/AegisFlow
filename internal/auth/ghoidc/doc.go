// Package ghoidc verifies GitHub Actions OIDC ID tokens, the credential CI jobs present to
// AegisFlow's ingestion and gate APIs (ARCHITECTURE.md §8, ADR-016).
//
// A workflow with `permissions: id-token: write` mints a short-lived RS256 JWT whose audience is
// AegisFlow's custom audience. The Verifier checks, in order:
//
//  1. Structure: compact JWS with three base64url segments, at most MaxTokenBytes, strict
//     base64url (no padding, no whitespace, canonical), JSON objects without duplicate keys.
//  2. Header: `alg` must be exactly RS256 (none, HS*, ES*, PS* and anything else are refused
//     with ErrUnsupportedAlg before any key is touched), `kid` is required, `crit` is refused.
//     Key material embedded in the token (`jwk`, `jku`, `x5u`, `x5c`) is never used.
//  3. Key: looked up by `kid` in the issuer's JWKS (RSA, `use`=sig, at least 2048 bits), cached
//     with a TTL, refreshed on an unknown `kid` at most once per minimum interval, and kept
//     (last known good) when a refresh fails.
//  4. Signature: RSASSA-PKCS1-v1_5 with SHA-256 over the exact signing input.
//  5. Claims: `iss` exact, `aud` contains the configured audience, `exp`/`nbf`/`iat` with a
//     bounded clock skew, required GitHub claims present, then authorization: `repository_id` and
//     `repository_owner_id` allow-lists (numeric IDs, never names, so a deleted-and-recreated or
//     renamed repository cannot inherit trust) and optional `ref`/`environment` allow-lists.
//
// The `sub` claim is exposed for audit only (see ParseSubject); it is never used for
// authorization because its format depends on repository age (GitHub's immutable subject format
// for repositories created after 2026-07-15) and on OIDC subject customisation.
//
// Middleware wraps an http.Handler, maps failures to RFC 9457 problem responses (401 with
// `WWW-Authenticate: Bearer`, 403 for identities outside the allow-lists, 503 when no signing key
// set is available) and exposes the verified Claims through ClaimsFromContext.
//
// The package uses only the Go standard library (crypto/rsa, crypto/sha256, encoding/json).
package ghoidc
