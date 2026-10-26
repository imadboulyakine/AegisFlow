package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// boundedText reports whether s is valid UTF-8 without NUL bytes and has minBytes..maxBytes bytes.
// Used for identity fields, which are rejected rather than altered.
func boundedText(s string, minBytes, maxBytes int) bool {
	return len(s) >= minBytes && len(s) <= maxBytes && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// cleanText makes descriptive text storable: it trims surrounding white space, replaces invalid
// UTF-8 and NUL (which PostgreSQL text and jsonb reject) with U+FFFD, and truncates to at most
// maxBytes bytes on a rune boundary. Used for titles, messages and similar free text.
func cleanText(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if strings.ContainsRune(s, 0) {
		s = strings.ReplaceAll(s, "\x00", "�")
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// cleanList cleans every element, drops empty ones and duplicates (keeping first occurrences),
// and keeps at most maxItems elements.
func cleanList(items []string, maxBytes, maxItems int) []string {
	out := make([]string, 0, min(len(items), maxItems))
	seen := make(map[string]struct{}, len(items))
	for _, it := range items {
		if len(out) == maxItems {
			break
		}
		c := cleanText(it, maxBytes)
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// isJSONObject reports whether b is a syntactically valid JSON object.
func isJSONObject(b []byte) bool {
	return json.Valid(b) && bytes.HasPrefix(bytes.TrimLeft(b, " \t\r\n"), []byte("{"))
}
