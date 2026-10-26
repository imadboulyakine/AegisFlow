package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"slices"
	"time"
)

// HeaderRequestID carries the correlation ID in requests and responses.
const HeaderRequestID = "X-Request-ID"

const maxRequestIDLen = 128

// contentSecurityPolicy is deliberately strict: no inline scripts or styles, no eval,
// no third-party origins. The Bun build fails if the emitted HTML would violate it.
const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; " +
	"object-src 'none'; form-action 'self'"

// permissionsPolicy disables powerful browser features the dashboard never needs.
const permissionsPolicy = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), " +
	"magnetometer=(), microphone=(), payment=(), usb=()"

type middleware func(http.Handler) http.Handler

// chain wraps h so that mws[0] is the outermost middleware.
func chain(h http.Handler, mws ...middleware) http.Handler {
	for _, mw := range slices.Backward(mws) {
		h = mw(h)
	}
	return h
}

type ctxKey int

const requestIDKey ctxKey = 0

// RequestIDFromContext returns the request ID assigned by the request ID middleware.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// validRequestID accepts short IDs made of URL-safe characters only, so a client-supplied
// value can be echoed and logged without enabling header or log injection.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := range len(id) {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// requestID propagates a valid incoming X-Request-ID or generates a random one.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if !validRequestID(id) {
			id = rand.Text() // 26 chars, 128 bits of entropy
		}
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// securityHeaders sets defensive response headers on every response.
//
// Strict-Transport-Security is intentionally NOT set here: TLS is terminated by the
// ingress (Azure Container Apps / local reverse proxy), which owns HSTS. Sending it
// from a plain-HTTP origin would be ignored at best and misleading at worst.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", permissionsPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// accessLog emits one structured log line per request. Query strings are not logged
// because they may carry tokens; health probes are logged at debug level to cut noise.
func accessLog(logger *slog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				level := slog.LevelInfo
				switch {
				case rec.status >= http.StatusInternalServerError:
					level = slog.LevelError
				case isProbe(r.URL.Path) && rec.status < http.StatusBadRequest:
					level = slog.LevelDebug
				}
				logger.LogAttrs(r.Context(), level, "http request",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", rec.status),
					slog.Int64("bytes", rec.bytes),
					slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
					slog.String("request_id", RequestIDFromContext(r.Context())),
					slog.String("remote_addr", r.RemoteAddr),
					slog.String("user_agent", truncate(r.UserAgent(), 256)),
					slog.String("proto", r.Proto),
				)
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// recoverPanics turns a handler panic into a 500 problem response and an error log
// with the stack trace, instead of letting net/http drop the connection.
func recoverPanics(logger *slog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v) // deliberate abort: let net/http close the connection quietly
				}
				logger.ErrorContext(r.Context(), "panic recovered",
					slog.String("panic", fmt.Sprint(v)),
					slog.String("stack", string(debug.Stack())),
					slog.String("request_id", RequestIDFromContext(r.Context())),
				)
				if rec.wroteHeader {
					// Too late for a clean error response; abort so the client sees a failure.
					panic(http.ErrAbortHandler)
				}
				// Drop representation headers the failed handler may have set for its own body.
				for _, k := range []string{"Content-Length", "Content-Encoding", "ETag", "Last-Modified"} {
					rec.Header().Del(k)
				}
				writeProblem(rec, r, http.StatusInternalServerError, "An unexpected error occurred.")
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

func isProbe(path string) bool { return path == "/healthz" || path == "/readyz" }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// responseRecorder captures the status code and body size written by inner handlers.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(code int) {
	// 1xx informational responses (except 101) may precede the final status.
	if !r.wroteHeader && (code >= 200 || code == http.StatusSwitchingProtocols) {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer (Flush, deadlines...).
func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
