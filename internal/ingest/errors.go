package ingest

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind classifies an ingest failure so the HTTP layer can map it to a status code without
// knowing the store's or the normalizer's error types.
type Kind int

// Error kinds.
const (
	// KindInternal is an unexpected failure (database down, bug). Its detail is generic.
	KindInternal Kind = iota
	// KindInvalidRequest is a malformed request (artifact, commit, format, claims).
	KindInvalidRequest
	// KindForbidden means the token may not submit this evidence (commit mismatch).
	KindForbidden
	// KindUnprocessable means the evidence was understood but rejected (format, validation).
	KindUnprocessable
	// KindTooLarge means the evidence exceeds a size or item limit.
	KindTooLarge
	// KindConflict means the request contradicts stored state (e.g. a run re-recorded with
	// another commit, an artifact digest recorded with another kind).
	KindConflict
)

func (k Kind) String() string {
	switch k {
	case KindInvalidRequest:
		return "invalid_request"
	case KindForbidden:
		return "forbidden"
	case KindUnprocessable:
		return "unprocessable"
	case KindTooLarge:
		return "too_large"
	case KindConflict:
		return "conflict"
	default:
		return "internal"
	}
}

// Error is the error type returned by Service.Ingest. Detail is safe to show to the
// authenticated caller; Err (possibly with internal details) is for logs only.
type Error struct {
	Kind   Kind
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("ingest: %s: %s: %v", e.Kind, e.Detail, e.Err)
	}
	return fmt.Sprintf("ingest: %s: %s", e.Kind, e.Detail)
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf returns the Kind of err (KindInternal when err is not an *Error).
func KindOf(err error) Kind {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Kind
	}
	return KindInternal
}

func fail(kind Kind, err error, format string, args ...any) *Error {
	return &Error{Kind: kind, Detail: fmt.Sprintf(format, args...), Err: err}
}

// maxDetailLen bounds error details derived from untrusted input.
const maxDetailLen = 512

// safeDetail makes an error message derived from untrusted input fit for a problem detail: one
// line, valid UTF-8, printable, bounded.
func safeDetail(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsPrint(r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > maxDetailLen {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
