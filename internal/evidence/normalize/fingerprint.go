package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// fingerprintDomain separates AegisFlow fingerprints from any other SHA-256 use and versions
// the scheme. Changing what is hashed (fields, canonicalization) MUST change this tag, because
// stored findings are tracked across runs by fingerprint.
const fingerprintDomain = "aegisflow/finding-fingerprint/v1"

// VulnFingerprint returns the fingerprint of a vulnerability finding: lowercase hex SHA-256 over
// the vulnerability ID and the package.
//
// Stability guarantees (scheme v1):
//   - deterministic and independent of the reporting tool, so the same advisory on the same
//     package from Grype, govulncheck or a CycloneDX VDR merges into one finding;
//   - vulnID is trimmed and upper-cased; callers should pass the canonical ID (the CVE when one
//     exists, as the normalizers do);
//   - purl is reduced with CanonicalPURL (qualifiers and subpath dropped, percent-decoding,
//     lowercase type), so "pkg:golang/golang.org%2Fx%2Ftext@v0.3.7" and
//     "pkg:golang/golang.org/x/text@v0.3.7?type=module" are the same package;
//   - the output for given inputs never changes within scheme v1.
func VulnFingerprint(vulnID, purl string) string {
	return hashFields("vuln", strings.ToUpper(strings.TrimSpace(vulnID)), CanonicalPURL(purl))
}

// LocationFingerprint returns the fingerprint of a code, secret or config finding: lowercase hex
// SHA-256 over the tool name (lower-cased; the tool version is deliberately excluded so that
// upgrades do not churn findings), the rule ID, the cleaned slash-separated path, the start line
// and, when snippet is non-empty, the SHA-256 of the snippet with whitespace runs collapsed.
//
// Only a hash of the snippet enters the fingerprint, never the snippet itself, so secret values
// reported by secret scanners are not reproduced. Including the line keeps two identical
// snippets in one file distinct; the trade-off is that inserting lines above a finding changes
// its fingerprint. The output for given inputs never changes within scheme v1.
func LocationFingerprint(tool, ruleID, filePath string, line int, snippet string) string {
	snippetHash := ""
	if s := strings.Join(strings.Fields(snippet), " "); s != "" {
		sum := sha256.Sum256([]byte(s))
		snippetHash = hex.EncodeToString(sum[:])
	}
	return hashFields("location",
		strings.ToLower(strings.TrimSpace(tool)),
		strings.TrimSpace(ruleID),
		cleanPath(filePath),
		strconv.Itoa(max(line, 0)),
		snippetHash,
	)
}

// hashFields hashes length-prefixed fields so that no two field lists collide by concatenation.
func hashFields(kind string, fields ...string) string {
	h := sha256.New()
	writeField(h, fingerprintDomain)
	writeField(h, kind)
	for _, f := range fields {
		writeField(h, f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h hash.Hash, s string) {
	_, _ = h.Write([]byte(strconv.Itoa(len(s))))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(s))
}

// cleanPath normalizes a slash-separated relative or absolute path: backslashes become slashes,
// "." and ".." elements are resolved lexically and a leading "./" is dropped. "" stays "".
func cleanPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	if p == "" {
		return ""
	}
	p = path.Clean(p)
	if p == "." {
		return ""
	}
	return p
}

// CanonicalPURL reduces a package URL to the form AegisFlow uses to compare packages across
// tools: "pkg:<type>/<namespace>/<name>@<version>" with
//   - the type lower-cased, qualifiers ("?…") and subpath ("#…") dropped;
//   - namespace, name and version percent-decoded (so an encoded "%2F" in a Go module name and
//     a literal "/" compare equal, as do "%40scope" and "@scope" for npm);
//   - PyPI names lower-cased with "_" replaced by "-" (purl-spec rule);
//   - for the Go standard library ("pkg:golang/stdlib"), a leading "go" or "v" removed from the
//     version, since syft, Grype and govulncheck spell it differently.
//
// Strings that are not package URLs are returned trimmed but otherwise unchanged.
func CanonicalPURL(purl string) string {
	typ, name, version, ok := splitPURL(purl)
	if !ok {
		return strings.TrimSpace(purl)
	}
	switch {
	case typ == "pypi":
		name = strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case typ == "golang" && name == "stdlib":
		version = strings.TrimPrefix(strings.TrimPrefix(version, "go"), "v")
	}
	// Re-escape the characters that decoding may have introduced and that would otherwise be
	// read back as separators, so that the canonical form parses back to itself (idempotence).
	// A leading "@" (npm scope) is kept in namespace segments.
	segs := strings.Split(name, "/")
	for i, seg := range segs {
		keep := 1
		if i == len(segs)-1 {
			keep = 0
		}
		keep = min(keep, len(seg))
		segs[i] = seg[:keep] + purlNameEscaper.Replace(seg[keep:])
	}
	out := "pkg:" + typ + "/" + strings.Join(segs, "/")
	if version != "" {
		out += "@" + purlVersionEscaper.Replace(version)
	}
	return out
}

var (
	purlNameEscaper    = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23", "@", "%40")
	purlVersionEscaper = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23", "@", "%40", "/", "%2F")
)

// splitPURL parses a package URL into its lower-cased type, its percent-decoded
// "namespace/name" path and its percent-decoded version, ignoring qualifiers and subpath.
// The version separator is the last "@" after the last "/", so unencoded npm scopes
// ("pkg:npm/@scope/name@1.0.0") are handled.
func splitPURL(purl string) (typ, name, version string, ok bool) {
	s := strings.TrimSpace(purl)
	if len(s) < 4 || !strings.EqualFold(s[:4], "pkg:") {
		return "", "", "", false
	}
	rest := s[4:]
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimLeft(rest, "/")
	typ, p, found := strings.Cut(rest, "/")
	if !found || typ == "" {
		return "", "", "", false
	}
	if i := strings.LastIndexByte(p, '@'); i > strings.LastIndexByte(p, '/') && i > 0 {
		p, version = p[:i], p[i+1:]
	}
	var segs []string
	for seg := range strings.SplitSeq(p, "/") {
		if u, err := url.PathUnescape(seg); err == nil {
			seg = u
		}
		// Decoded "%2F" splits a segment; empty segments are dropped.
		for part := range strings.SplitSeq(seg, "/") {
			if part != "" {
				segs = append(segs, part)
			}
		}
	}
	name = strings.Join(segs, "/")
	if name == "" {
		return "", "", "", false
	}
	if u, err := url.PathUnescape(version); err == nil {
		version = u
	}
	return strings.ToLower(typ), name, version, true
}
