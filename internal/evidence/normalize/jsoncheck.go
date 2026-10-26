package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// checkJSON pre-validates untrusted JSON before it is decoded into format structs:
//
//   - it must be well-formed, non-empty JSON;
//   - nesting depth is bounded by maxDepth;
//   - no object may contain two keys that encoding/json would treat as the same field
//     (exact duplicates or keys equal under Unicode case folding). encoding/json silently keeps
//     the last one, which would let a crafted document show one value to a human or another
//     parser and a different one to AegisFlow;
//   - unless stream is true (govulncheck emits a sequence of JSON values), exactly one top-level
//     value is allowed: trailing data is rejected.
func checkJSON(data []byte, maxDepth int, stream bool) error {
	type frame struct {
		object  bool
		wantKey bool
		keys    map[string]struct{}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // numbers are only skipped here; avoid float parsing
	var stack []frame
	values := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return invalidf("malformed JSON: %v", err)
		}
		if len(stack) == 0 {
			values++
			if values > 1 && !stream {
				return invalidf("unexpected data after the top-level JSON value")
			}
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= maxDepth {
					return fmt.Errorf("%w: JSON nesting deeper than %d", ErrLimitExceeded, maxDepth)
				}
				stack = append(stack, frame{object: t == '{', wantKey: t == '{'})
				continue
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey {
				top := &stack[n-1]
				k := foldKey(t)
				if top.keys == nil {
					top.keys = make(map[string]struct{})
				}
				if _, dup := top.keys[k]; dup {
					return invalidf("duplicate object key %q", clip(t, 64))
				}
				top.keys[k] = struct{}{}
				top.wantKey = false
				continue
			}
		}
		// A complete value was consumed; an enclosing object now expects its next key.
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
	if values == 0 {
		return invalidf("empty document")
	}
	return nil
}

// foldKey maps s to a canonical form such that foldKey(a) == foldKey(b) exactly when
// encoding/json would match a and b to the same struct field (bytes.EqualFold semantics).
func foldKey(s string) string {
	var b []byte
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			b = append(b, c)
			i++
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		b = utf8.AppendRune(b, foldRune(r))
		i += n
	}
	return string(b)
}

// foldRune returns the smallest rune in r's Unicode simple case-folding orbit.
func foldRune(r rune) rune {
	for {
		r2 := unicode.SimpleFold(r)
		if r2 <= r {
			return r2
		}
		r = r2
	}
}
