// Test cases for go-slog-sensitive-data (run: make sast-test). Values are placeholders.
package semgreptest

import (
	"context"
	"log/slog"
	"net/http"
)

func goodAccessLog(logger *slog.Logger, r *http.Request, status int) {
	// ok: go-slog-sensitive-data
	logger.Info("request",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", status),
		slog.String("request_id", r.Header.Get("X-Request-ID")),
		slog.String("user_agent", r.UserAgent()),
	)
}

func goodVerifiedClaims(ctx context.Context, logger *slog.Logger, subject string, hasToken bool) {
	// ok: go-slog-sensitive-data
	logger.InfoContext(ctx, "evidence accepted", "subject", subject, "token_present", hasToken)
}

func badTypedAttr(logger *slog.Logger, token string) {
	// ruleid: go-slog-sensitive-data
	logger.Info("ingest", slog.String("token", token))
}

func badAccessTokenAny(logger *slog.Logger, v any) {
	// ruleid: go-slog-sensitive-data
	logger.Debug("oidc", slog.Any("github.access_token", v))
}

func badKeyValue(logger *slog.Logger, pw string) {
	// ruleid: go-slog-sensitive-data
	logger.Warn("login failed", "user", "admin", "password", pw)
}

func badKeyValueContext(ctx context.Context, logger *slog.Logger, secret string) {
	// ruleid: go-slog-sensitive-data
	logger.ErrorContext(ctx, "azure call failed", "client_secret", secret)
}

func badWith(logger *slog.Logger, key string) *slog.Logger {
	// ruleid: go-slog-sensitive-data
	return logger.With("api_key", key)
}

func badHeaderMap(logger *slog.Logger, r *http.Request) {
	// ruleid: go-slog-sensitive-data
	logger.Info("request", slog.Any("headers", r.Header))
}

func badAuthorizationHeader(logger *slog.Logger, r *http.Request) {
	// ruleid: go-slog-sensitive-data
	logger.Info("request", "auth", r.Header.Get("Authorization"))
}

func badCookies(logger *slog.Logger, r *http.Request) {
	// ruleid: go-slog-sensitive-data
	logger.Debug("request", slog.Any("c", r.Cookies()))
}
