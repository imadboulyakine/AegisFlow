package normalize

import (
	"encoding/json"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// Text limits for human-readable fields copied from untrusted input.
const (
	maxTitleLen   = 256
	maxMessageLen = 4096
)

// SeverityFromScore maps a CVSS-style 0–10 score to a severity band: ≥9 critical, ≥7 high,
// ≥4 medium, >0 low, 0 info. Scores outside [0, 10] (or NaN) are unknown.
func SeverityFromScore(score float64) evidence.Severity {
	switch {
	case math.IsNaN(score) || score < 0 || score > 10:
		return evidence.SeverityUnknown
	case score >= 9:
		return evidence.SeverityCritical
	case score >= 7:
		return evidence.SeverityHigh
	case score >= 4:
		return evidence.SeverityMedium
	case score > 0:
		return evidence.SeverityLow
	default:
		return evidence.SeverityInfo
	}
}

// maxSeverity returns the higher-ranked severity.
func maxSeverity(a, b evidence.Severity) evidence.Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// severityFromCVSS returns the band of the highest valid base score, or unknown.
func severityFromCVSS(cvss []evidence.CVSS) evidence.Severity {
	sev := evidence.SeverityUnknown
	for _, c := range cvss {
		sev = maxSeverity(sev, SeverityFromScore(c.BaseScore))
	}
	return sev
}

// normalizeCVSSVersion returns "2.0", "3.0", "3.1" or "4.0", or "" when v is not one of them.
// When v is empty the version is taken from the vector prefix ("CVSS:3.1/…"; v2 vectors have no
// prefix and are recognized by their "AV:…/Au:" shape).
func normalizeCVSSVersion(v, vector string) string {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	if v == "" {
		switch {
		case strings.HasPrefix(vector, "CVSS:"):
			v, _, _ = strings.Cut(strings.TrimPrefix(vector, "CVSS:"), "/")
		case strings.Contains(vector, "Au:"):
			v = "2.0"
		}
	}
	switch v {
	case "2", "2.0":
		return "2.0"
	case "3", "3.0":
		return "3.0"
	case "3.1":
		return "3.1"
	case "4", "4.0":
		return "4.0"
	default:
		return ""
	}
}

// newCVSS validates and builds a CVSS rating; ok is false for unknown versions or scores outside
// [0, 10].
func newCVSS(version, vector string, score float64) (evidence.CVSS, bool) {
	ver := normalizeCVSSVersion(version, vector)
	if ver == "" || math.IsNaN(score) || score < 0 || score > 10 {
		return evidence.CVSS{}, false
	}
	return evidence.CVSS{Version: ver, Vector: strings.TrimSpace(vector), BaseScore: score}, true
}

// appendCVSS appends c unless an identical rating is already present.
func appendCVSS(dst []evidence.CVSS, c evidence.CVSS) []evidence.CVSS {
	if slices.Contains(dst, c) {
		return dst
	}
	return append(dst, c)
}

// imageRepository strips the tag and digest from an image reference
// ("ghcr.io/o/app:1.0@sha256:…" → "ghcr.io/o/app"); a ':' before the last '/' is a registry port.
func imageRepository(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	return ref
}

// newArtifact builds a subject; container image names are reduced to the repository.
func newArtifact(kind evidence.ArtifactKind, name, digest string) *evidence.Artifact {
	if kind == evidence.ArtifactContainerImage {
		name = imageRepository(name)
	}
	return &evidence.Artifact{Kind: kind, Name: name, Digest: digest}
}

// vulnIDFromIRI returns the advisory ID at the end of an advisory URL
// ("https://pkg.go.dev/vuln/GO-2022-1059" → "GO-2022-1059"); other strings are returned as is.
func vulnIDFromIRI(s string) string {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return s
	}
	seg := u.Path[strings.LastIndexByte(u.Path, '/')+1:]
	prefix, rest, ok := strings.Cut(seg, "-")
	if !ok || rest == "" || prefix == "" || strings.ToUpper(prefix) != prefix || strings.ContainsAny(prefix, "0123456789") {
		return s
	}
	return seg
}

// canonicalVulnID picks the canonical identifier among primary and aliases (the first CVE,
// upper-cased, else primary) and returns the remaining distinct identifiers.
func canonicalVulnID(primary string, aliases []string) (string, []string) {
	var ids []string
	for _, id := range append([]string{primary}, aliases...) {
		id = strings.TrimSpace(id)
		if len(id) >= 4 && strings.EqualFold(id[:4], "CVE-") {
			id = strings.ToUpper(id)
		}
		if id != "" {
			ids = appendUnique(ids, id)
		}
	}
	if len(ids) == 0 {
		return "", nil
	}
	canonical := ids[0]
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			canonical = id
			break
		}
	}
	rest := make([]string, 0, len(ids)-1)
	for _, id := range ids {
		if id != canonical {
			rest = append(rest, id)
		}
	}
	if len(rest) == 0 {
		rest = nil
	}
	return canonical, rest
}

// validPURL reports whether s looks like a package URL with a type and a name.
func validPURL(s string) bool {
	return evidence.EcosystemFromPURL(s) != "" && !strings.ContainsAny(s, " \t\r\n")
}

// genericPURL synthesizes "pkg:generic/<name>@<version>" for packages a tool reported without a
// PURL, so that they can still be keyed and fingerprinted.
func genericPURL(name, version string) string {
	p := "pkg:generic/" + url.PathEscape(name)
	if version != "" {
		p += "@" + url.PathEscape(version)
	}
	return p
}

// newComponent builds a Component; when purl is not a valid package URL a generic one is
// synthesized from name and version.
func newComponent(purl, name, version string, licenses []string) evidence.Component {
	purl = strings.TrimSpace(purl)
	if !validPURL(purl) {
		purl = genericPURL(name, version)
	}
	return evidence.Component{
		PURL:      purl,
		Name:      name,
		Version:   version,
		Ecosystem: evidence.EcosystemFromPURL(purl),
		Licenses:  licenses,
	}
}

// vulnTitle formats the title of a vulnerability finding.
func vulnTitle(id string, c *evidence.Component) string {
	if c == nil || c.Name == "" {
		return clip(id, maxTitleLen)
	}
	t := id + " in " + c.Name
	if c.Version != "" {
		t += "@" + c.Version
	}
	return clip(t, maxTitleLen)
}

// digest hex lengths by algorithm.
var digestHexLen = map[string]int{"sha256": 64, "sha384": 96, "sha512": 128}

// normalizeDigest validates "<alg>:<hex>" (also "<alg>-<hex>" and percent-encoded ':'), and
// returns it lower-cased. ok is false for anything else.
func normalizeDigest(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "%3a", ":")
	alg, hexPart, found := strings.Cut(s, ":")
	if !found {
		alg, hexPart, found = strings.Cut(s, "-")
	}
	if !found {
		return "", false
	}
	alg = strings.ReplaceAll(alg, "-", "")
	n, known := digestHexLen[alg]
	if !known || len(hexPart) != n || !isHex(hexPart) {
		return "", false
	}
	return alg + ":" + hexPart, true
}

// digestFromChecksum builds a digest from an algorithm name as SBOMs spell it ("SHA-256",
// "SHA256", "sha256") and a hex value.
func digestFromChecksum(alg, value string) (string, bool) {
	return normalizeDigest(strings.ReplaceAll(strings.ToLower(alg), "-", "") + ":" + value)
}

// digestFromOCIPURL extracts the digest from a "pkg:oci/<name>@sha256%3A<hex>" package URL.
func digestFromOCIPURL(purl string) (string, bool) {
	if evidence.EcosystemFromPURL(purl) != "oci" {
		return "", false
	}
	rest := purl
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	i := strings.LastIndexByte(rest, '@')
	if i < 0 {
		return "", false
	}
	v, err := url.PathUnescape(rest[i+1:])
	if err != nil {
		return "", false
	}
	return normalizeDigest(v)
}

// digestFromReference extracts the digest from "repo@sha256:<hex>" or a bare digest.
func digestFromReference(ref string) (string, bool) {
	if i := strings.LastIndexByte(ref, '@'); i >= 0 {
		ref = ref[i+1:]
	}
	return normalizeDigest(ref)
}

func isHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return s != ""
}

// artifactKind maps an SBOM subject type (CycloneDX component type or SPDX primary package
// purpose, any case) to an ArtifactKind.
func artifactKind(typ string, hasDigest bool) evidence.ArtifactKind {
	switch strings.ToLower(strings.ReplaceAll(typ, "_", "-")) {
	case "container":
		return evidence.ArtifactContainerImage
	case "source":
		return evidence.ArtifactSource
	case "file", "archive", "firmware", "device", "install", "operating-system":
		if hasDigest {
			return evidence.ArtifactBinary
		}
		return evidence.ArtifactSource
	default:
		return evidence.ArtifactSource
	}
}

// appendUnique appends the non-empty values of add that are not yet in dst.
func appendUnique(dst []string, add ...string) []string {
	for _, s := range add {
		if s == "" {
			continue
		}
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// clip truncates s to at most n bytes on a UTF-8 boundary, marking truncation with "…".
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	cut := max(n-len(ellipsis), 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}

// firstLine returns the first non-empty line of s, trimmed.
func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// parseTime parses an RFC 3339 timestamp; ok is false for empty or invalid input.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// flexFloat decodes a JSON number or a numeric string ("7.5"), as tools disagree on the type of
// SARIF security-severity. Invalid values decode as "not set" instead of failing the document.
type flexFloat struct {
	Value float64
	Set   bool
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexFloat) UnmarshalJSON(b []byte) error {
	*f = flexFloat{}
	if string(b) == "null" {
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err == nil {
		*f = flexFloat{Value: n, Set: true}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
			*f = flexFloat{Value: v, Set: true}
		}
	}
	return nil
}

// dependencyGraph derives first-level ("direct") dependencies from SBOM dependency edges.
type dependencyGraph struct {
	out      map[string][]string
	incoming map[string]bool
}

func newDependencyGraph() *dependencyGraph {
	return &dependencyGraph{out: map[string][]string{}, incoming: map[string]bool{}}
}

func (g *dependencyGraph) addEdge(from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	g.out[from] = append(g.out[from], to)
	g.incoming[to] = true
}

// direct returns the refs directly depended on by the root. The root is primary when it has
// outgoing edges; otherwise every graph root (outgoing edges, no incoming edge) for which
// isProjectRoot is true — used for syft, which hangs the project's own main module (an
// unversioned package) rather than the document subject at the top of the graph.
func (g *dependencyGraph) direct(primary string, isProjectRoot func(ref string) bool) map[string]bool {
	roots := []string{}
	if len(g.out[primary]) > 0 {
		roots = append(roots, primary)
	} else {
		for ref := range g.out {
			if !g.incoming[ref] && isProjectRoot(ref) {
				roots = append(roots, ref)
			}
		}
	}
	direct := map[string]bool{}
	for _, r := range roots {
		for _, to := range g.out[r] {
			direct[to] = true
		}
	}
	return direct
}

// unversioned reports whether a package version denotes an in-tree, unreleased project.
func unversioned(v string) bool {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "UNKNOWN", "(DEVEL)", "NOASSERTION":
		return true
	default:
		return false
	}
}
