package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/auth/ghoidc"
	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/ingest"
)

// Ingestion route and limits. The ingest route is the only one that accepts a large body; the
// limit is applied after authentication-independent routing but the body is only read once the
// OIDC middleware has accepted the token.
const (
	ingestPath = "/api/v1/ingest"
	// maxIngestBodyBytes is 16 MiB of base64 evidence (12 MiB decoded) plus 64 KiB of envelope.
	maxIngestBodyBytes = 16<<20 + 64<<10
	// Authenticated uploads get longer deadlines than the server-wide ReadTimeout/WriteTimeout.
	ingestReadTimeout  = 2 * time.Minute
	ingestWriteTimeout = 3 * time.Minute
)

// Ingester is the evidence-ingestion service (internal/ingest.Service).
type Ingester interface {
	Ingest(ctx context.Context, claims *ghoidc.Claims, req ingest.Request) (ingest.Result, error)
}

// ingestEnvelope is the JSON body of POST /api/v1/ingest. The evidence file travels base64-encoded
// so that the stored bytes, and therefore the recorded SHA-256, are exactly the file CI produced.
type ingestEnvelope struct {
	Artifact *evidence.Artifact `json:"artifact"`
	Commit   string             `json:"commit"`
	Format   evidence.Format    `json:"format"`
	// Evidence is the standard base64 encoding of the evidence file.
	Evidence string `json:"evidence"`
	// EvidenceSHA256 optionally lets the client assert the hex SHA-256 of the decoded file.
	EvidenceSHA256 string `json:"evidenceSha256"`
}

// limitBody caps request bodies: maxIngestBodyBytes for POST /api/v1/ingest, maxBodyBytes for
// everything else.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(maxBodyBytes)
		if r.Method == http.MethodPost && r.URL.Path == ingestPath {
			limit = maxIngestBodyBytes
		}
		r2 := *r
		r2.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, &r2)
	})
}

// ingestHandler returns the handler for POST /api/v1/ingest: the OIDC middleware followed by
// handleIngest, or a 503 problem when ingestion is not configured.
func (s *Server) ingestHandler() http.Handler {
	if s.verifier == nil || s.ingester == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeProblem(w, r, http.StatusServiceUnavailable,
				"Evidence ingestion is not configured on this server (database and OIDC settings are required).")
		})
	}
	auth := ghoidc.Middleware(s.verifier,
		ghoidc.WithLogger(s.logger),
		ghoidc.WithErrorWriter(func(w http.ResponseWriter, r *http.Request, status int, detail string) {
			writeProblem(w, r, status, detail)
		}),
	)
	return auth(http.HandlerFunc(s.handleIngest))
}

// handleIngest decodes the envelope and runs the ingest service. It expects verified claims in the
// request context (set by the OIDC middleware, or by ghoidc.ContextWithClaims in tests).
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	claims, ok := ghoidc.ClaimsFromContext(r.Context())
	if !ok || s.ingester == nil {
		writeProblem(w, r, http.StatusInternalServerError, "An unexpected error occurred.")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(ingestReadTimeout)) // not supported by test recorders
	_ = rc.SetWriteDeadline(time.Now().Add(ingestWriteTimeout))

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != contentTypeJSON {
		writeProblem(w, r, http.StatusUnsupportedMediaType, "The request body must be application/json.")
		return
	}
	req, status, detail := decodeIngest(r.Body)
	if status != 0 {
		writeProblem(w, r, status, detail)
		return
	}

	res, err := s.ingester.Ingest(r.Context(), claims, req)
	if err != nil {
		s.ingestFailed(w, r, err)
		return
	}
	code := http.StatusOK
	if res.Evidence.Created {
		code = http.StatusCreated
	}
	writeJSON(w, code, contentTypeJSON, res)
}

// decodeIngest parses and validates the envelope. A non-zero status means failure.
func decodeIngest(body io.Reader) (ingest.Request, int, string) {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	var env ingestEnvelope
	if err := dec.Decode(&env); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return ingest.Request{}, http.StatusRequestEntityTooLarge, "The request body exceeds the ingestion limit."
		}
		return ingest.Request{}, http.StatusBadRequest, "The request body is not a valid ingestion envelope: " + jsonErrorDetail(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return ingest.Request{}, http.StatusRequestEntityTooLarge, "The request body exceeds the ingestion limit."
		}
		return ingest.Request{}, http.StatusBadRequest, "The request body must contain a single JSON object."
	}
	if env.Artifact == nil {
		return ingest.Request{}, http.StatusBadRequest, "artifact is required."
	}
	if env.Evidence == "" {
		return ingest.Request{}, http.StatusBadRequest, "evidence (base64-encoded file) is required."
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(env.Evidence)
	if err != nil {
		return ingest.Request{}, http.StatusBadRequest, "evidence must be standard base64 (RFC 4648 §4, padded)."
	}
	if env.EvidenceSHA256 != "" {
		sum := sha256.Sum256(raw)
		if !strings.EqualFold(env.EvidenceSHA256, hex.EncodeToString(sum[:])) {
			return ingest.Request{}, http.StatusUnprocessableEntity, "evidenceSha256 does not match the decoded evidence."
		}
	}
	return ingest.Request{
		Artifact: *env.Artifact, Commit: env.Commit, Format: env.Format, Evidence: raw,
	}, 0, ""
}

// jsonErrorDetail describes a JSON decoding error without echoing request content.
func jsonErrorDetail(err error) string {
	if _, ok := errors.AsType[*json.SyntaxError](err); ok {
		return "malformed JSON."
	}
	if te, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return "field " + te.Field + " has the wrong type."
	}
	if field, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return "unknown field " + field + "."
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "empty or truncated body."
	}
	return "malformed JSON."
}

// ingestFailed maps an ingest error to a problem response.
func (s *Server) ingestFailed(w http.ResponseWriter, r *http.Request, err error) {
	var detail string
	if e, ok := errors.AsType[*ingest.Error](err); ok {
		detail = e.Detail
	}
	status := http.StatusInternalServerError
	switch ingest.KindOf(err) {
	case ingest.KindInvalidRequest:
		status = http.StatusBadRequest
	case ingest.KindForbidden:
		status = http.StatusForbidden
	case ingest.KindUnprocessable:
		status = http.StatusUnprocessableEntity
	case ingest.KindTooLarge:
		status = http.StatusRequestEntityTooLarge
	case ingest.KindConflict:
		status = http.StatusConflict
	}
	level := slog.LevelWarn
	if status == http.StatusInternalServerError {
		level = slog.LevelError
		detail = "An unexpected error occurred while ingesting the evidence."
	}
	s.logger.LogAttrs(r.Context(), level, "evidence ingest rejected",
		slog.Int("status", status),
		slog.String("kind", ingest.KindOf(err).String()),
		slog.String("error", err.Error()),
		slog.String("request_id", RequestIDFromContext(r.Context())),
	)
	writeProblem(w, r, status, detail)
}
