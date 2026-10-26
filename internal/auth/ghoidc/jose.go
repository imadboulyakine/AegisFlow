package ghoidc

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	algRS256 = "RS256"
	// maxKIDLen bounds the key ID; GitHub uses short opaque IDs.
	maxKIDLen = 256
	// maxJSONKeys bounds the members of a header or claims object.
	maxJSONKeys = 256
	// maxSignatureBytes is the signature size of the largest accepted key (8192 bits).
	maxSignatureBytes = maxRSABits / 8
)

// rawURL is strict base64url without padding: it rejects '=' and non-zero trailing bits, so
// every token has exactly one accepted encoding.
var rawURL = base64.RawURLEncoding.Strict()

// jws is a parsed compact JWS whose signature has not been verified yet.
type jws struct {
	alg, kid     string
	signingInput string // "<header>.<payload>" exactly as received
	payload      []byte
	signature    []byte
}

// parseCompact splits and decodes a compact JWS and validates its protected header. It never
// trusts the payload: that is decoded only after the signature has been verified.
func parseCompact(token string) (*jws, error) {
	if len(token) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: token is %d bytes, limit is %d", ErrMalformed, len(token), MaxTokenBytes)
	}
	if strings.Count(token, ".") != 2 {
		return nil, fmt.Errorf("%w: compact JWS must have exactly 3 segments", ErrMalformed)
	}
	h64, rest, _ := strings.Cut(token, ".")
	p64, s64, _ := strings.Cut(rest, ".")
	if h64 == "" || p64 == "" {
		return nil, fmt.Errorf("%w: empty header or payload segment", ErrMalformed)
	}

	headerJSON, err := decodeSegment(h64)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	alg, kid, err := parseHeader(headerJSON)
	if err != nil {
		return nil, err
	}

	payload, err := decodeSegment(p64)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	if s64 == "" {
		return nil, fmt.Errorf("%w: missing signature", ErrMalformed)
	}
	if len(s64) > rawURL.EncodedLen(maxSignatureBytes) {
		return nil, fmt.Errorf("%w: signature longer than any accepted key", ErrMalformed)
	}
	sig, err := decodeSegment(s64)
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %w", ErrMalformed, err)
	}
	return &jws{
		alg:          alg,
		kid:          kid,
		signingInput: token[:len(h64)+1+len(p64)],
		payload:      payload,
		signature:    sig,
	}, nil
}

// decodeSegment decodes one base64url segment, refusing anything outside the URL-safe alphabet
// (the standard decoder would silently skip CR/LF).
func decodeSegment(s string) ([]byte, error) {
	for i := range len(s) {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return nil, fmt.Errorf("invalid base64url character at offset %d", i)
		}
	}
	b, err := rawURL.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return b, nil
}

// parseHeader validates the protected header: alg first (so `none` and HMAC tokens are reported
// as such even without a kid), then kid, typ and crit. Other parameters, including embedded key
// material (jwk, jku, x5u, x5c), are ignored and never used to select or build a key.
func parseHeader(b []byte) (alg, kid string, err error) {
	h, err := parseObject(b)
	if err != nil {
		return "", "", fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	alg, ok, err := stringMember(h, "alg")
	if err != nil {
		return "", "", fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if !ok || alg == "" {
		return "", "", fmt.Errorf("%w: header: missing alg", ErrMalformed)
	}
	if alg != algRS256 {
		return "", "", unsupportedAlg(alg)
	}
	kid, ok, err = stringMember(h, "kid")
	if err != nil {
		return "", "", fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if !ok || kid == "" {
		return "", "", fmt.Errorf("%w: header: missing kid", ErrMalformed)
	}
	if len(kid) > maxKIDLen {
		return "", "", fmt.Errorf("%w: header: kid longer than %d bytes", ErrMalformed, maxKIDLen)
	}
	typ, ok, err := stringMember(h, "typ")
	if err != nil {
		return "", "", fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if ok && !strings.EqualFold(typ, "JWT") {
		return "", "", fmt.Errorf("%w: header: typ %s is not JWT", ErrMalformed, quote(typ))
	}
	if _, ok := h["crit"]; ok {
		return "", "", fmt.Errorf("%w: header: critical extensions are not supported", ErrMalformed)
	}
	return alg, kid, nil
}

// unsupportedAlg explains why an algorithm is refused. The distinction matters in logs: `none`
// and HMAC-with-the-public-key are classic forgery attempts, not misconfigurations.
func unsupportedAlg(alg string) error {
	switch {
	case strings.EqualFold(alg, "none"):
		return fmt.Errorf("%w: unsecured JWS (alg %s) is never accepted", ErrUnsupportedAlg, quote(alg))
	case len(alg) >= 2 && strings.EqualFold(alg[:2], "HS"):
		return fmt.Errorf("%w: symmetric alg %s is never accepted (algorithm confusion)", ErrUnsupportedAlg, quote(alg))
	default:
		return fmt.Errorf("%w: alg %s is not accepted, only RS256", ErrUnsupportedAlg, quote(alg))
	}
}

// verifyRS256 checks an RSASSA-PKCS1-v1_5 SHA-256 signature over the signing input.
func verifyRS256(key *rsa.PublicKey, signingInput string, sig []byte) error {
	if len(sig) != key.Size() {
		return fmt.Errorf("%w: signature is %d bytes, key requires %d", ErrSignature, len(sig), key.Size())
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return nil
}

// parseObject decodes a JSON object into its raw members, rejecting invalid UTF-8, non-object
// values, duplicate member names (which parsers resolve differently) and trailing data. Member
// names are matched exactly later on; encoding/json's case-insensitive struct matching is never
// applied to untrusted token JSON.
func parseObject(b []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("json: not an object")
	}
	members := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("json: invalid member name")
		}
		if _, dup := members[name]; dup {
			return nil, fmt.Errorf("json: duplicate member %s", quote(name))
		}
		if len(members) == maxJSONKeys {
			return nil, fmt.Errorf("json: more than %d members", maxJSONKeys)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("json: member %s: %w", quote(name), err)
		}
		members[name] = raw
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, fmt.Errorf("json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("json: trailing data after object")
	}
	return members, nil
}

// stringMember returns a string member. Absent and null members report ok=false; any other
// JSON type is an error (no number-to-string coercion).
func stringMember(m map[string]json.RawMessage, name string) (s string, ok bool, err error) {
	raw, present := m[name]
	if !present || isNull(raw) {
		return "", false, nil
	}
	if len(raw) == 0 || raw[0] != '"' {
		return "", false, fmt.Errorf("member %s must be a string", quote(name))
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, fmt.Errorf("member %s: %w", quote(name), err)
	}
	return s, true, nil
}

func isNull(raw json.RawMessage) bool { return string(raw) == "null" }

// quote renders an untrusted value for an error message: truncated and Go-quoted so it cannot
// inject control characters into logs.
func quote(s string) string {
	const maxLen = 64
	if len(s) > maxLen {
		return fmt.Sprintf("%q…", s[:maxLen])
	}
	return fmt.Sprintf("%q", s)
}
