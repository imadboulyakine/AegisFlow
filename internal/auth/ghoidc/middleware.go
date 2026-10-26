package ghoidc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
)

const (
	contentTypeProblem = "application/problem+json"
	realm              = "aegisflow"
)

type claimsKey struct{}

// ContextWithClaims returns a copy of ctx carrying c. Middleware uses it; handler tests in other
// packages can use it to simulate an authenticated workflow.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// ClaimsFromContext returns the verified claims stored by Middleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok && c != nil
}

// ErrorWriter renders a rejected request. Middleware has already set WWW-Authenticate (401) or
// Retry-After (503) when it calls the writer. detail is safe to show to clients.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, status int, detail string)

// MiddlewareOption customises Middleware.
type MiddlewareOption func(*middlewareOptions)

type middlewareOptions struct {
	logger      *slog.Logger
	writeError  ErrorWriter
	retryAfterS int
}

// WithLogger logs every rejection (Warn, with the internal reason) and every accepted workflow
// identity (Debug). Tokens are never logged. Without it nothing is logged.
func WithLogger(l *slog.Logger) MiddlewareOption {
	return func(o *middlewareOptions) { o.logger = l }
}

// WithErrorWriter replaces the default RFC 9457 problem writer, e.g. to add the server's
// request ID to error bodies.
func WithErrorWriter(fn ErrorWriter) MiddlewareOption {
	return func(o *middlewareOptions) {
		if fn != nil {
			o.writeError = fn
		}
	}
}

// Middleware authenticates every request with a GitHub Actions OIDC bearer token. Accepted
// requests reach next with the Claims in their context (ClaimsFromContext). Rejections:
//   - 401 + `WWW-Authenticate: Bearer realm="aegisflow"[, error="invalid_token"]` when the token
//     is missing, malformed, badly signed, expired, or for another issuer/audience;
//   - 403 when the token is authentic but its repository, owner, ref or environment is not allowed;
//   - 503 + Retry-After when no signing key set is available (issuer unreachable at startup);
//   - 500 when v is nil (fail closed on a wiring bug).
//
// Problem details are generic: the precise reason goes to the log (WithLogger), not the client.
func Middleware(v *Verifier, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	o := middlewareOptions{writeError: writeProblem, retryAfterS: 30}
	for _, opt := range opts {
		opt(&o)
	}
	if v != nil {
		o.retryAfterS = max(1, int(math.Ceil(v.keys.minInterval.Seconds())))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v == nil {
				o.reject(w, r, http.StatusInternalServerError, "misconfigured", "authentication is not configured", nil)
				return
			}
			token, err := bearerToken(r)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
				o.reject(w, r, http.StatusUnauthorized, "missing_token", "a GitHub Actions OIDC bearer token is required", err)
				return
			}
			claims, err := v.Verify(r.Context(), token)
			if err != nil {
				status, detail := classify(err)
				switch status {
				case http.StatusUnauthorized:
					w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`", error="invalid_token"`)
				case http.StatusServiceUnavailable:
					w.Header().Set("Retry-After", strconv.Itoa(o.retryAfterS))
				}
				o.reject(w, r, status, reasonOf(err), detail, err)
				return
			}
			if o.logger != nil {
				o.logger.LogAttrs(r.Context(), slog.LevelDebug, "oidc token accepted",
					slog.String("repository", claims.Repository),
					slog.String("repository_id", claims.RepositoryID),
					slog.String("ref", claims.Ref),
					slog.String("sha", claims.SHA),
					slog.String("run_id", claims.RunID),
					slog.String("event_name", claims.EventName))
			}
			next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
		})
	}
}

func (o *middlewareOptions) reject(w http.ResponseWriter, r *http.Request, status int, reason, detail string, err error) {
	if o.logger != nil {
		attrs := []slog.Attr{
			slog.Int("status", status),
			slog.String("reason", reason),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
		}
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		o.logger.LogAttrs(r.Context(), slog.LevelWarn, "oidc authentication rejected", attrs...)
	}
	o.writeError(w, r, status, detail)
}

var errNoBearer = errors.New("no bearer token")

// bearerToken extracts the token of a single `Authorization: Bearer <token>` header (RFC 6750
// §2.1; the scheme is case-insensitive).
func bearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", errNoBearer
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", errNoBearer
	}
	token = strings.TrimLeft(token, " ")
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", errNoBearer
	}
	return token, nil
}

// classify maps a Verify error to an HTTP status and a client-safe detail.
func classify(err error) (int, string) {
	switch {
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden, "the workflow identity is not authorized for this API"
	case errors.Is(err, ErrJWKSUnavailable):
		return http.StatusServiceUnavailable, "token verification is temporarily unavailable"
	case errors.Is(err, ErrExpired), errors.Is(err, ErrNotYetValid):
		return http.StatusUnauthorized, "the token is expired or not yet valid"
	case errors.Is(err, ErrIssuer), errors.Is(err, ErrAudience):
		return http.StatusUnauthorized, "the token issuer or audience is not accepted"
	case errors.Is(err, ErrMalformed), errors.Is(err, ErrMissingClaim):
		return http.StatusUnauthorized, "the token is malformed"
	default: // ErrUnsupportedAlg, ErrUnknownKey, ErrSignature
		return http.StatusUnauthorized, "the token signature could not be verified"
	}
}

// reasons maps sentinels to stable log reason codes, most specific first.
var reasons = []struct {
	err  error
	code string
}{
	{ErrRepositoryNotAllowed, "repository_not_allowed"},
	{ErrRefNotAllowed, "ref_not_allowed"},
	{ErrEnvironmentNotAllowed, "environment_not_allowed"},
	{ErrJWKSUnavailable, "jwks_unavailable"},
	{ErrUnsupportedAlg, "unsupported_alg"},
	{ErrUnknownKey, "unknown_key"},
	{ErrSignature, "bad_signature"},
	{ErrMalformed, "malformed"},
	{ErrMissingClaim, "missing_claim"},
	{ErrIssuer, "bad_issuer"},
	{ErrAudience, "bad_audience"},
	{ErrExpired, "expired"},
	{ErrNotYetValid, "not_yet_valid"},
	{ErrForbidden, "forbidden"},
}

func reasonOf(err error) string {
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			return r.code
		}
	}
	return "invalid_token"
}

// problem is an RFC 9457 "Problem Details for HTTP APIs" body (same shape as internal/server).
type problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// writeProblem is the default ErrorWriter.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, detail string) {
	body, err := json.Marshal(problem{
		Type:     "about:blank",
		Title:    http.StatusText(status),
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
	})
	if err != nil { // unreachable: the struct always marshals
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentTypeProblem)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
