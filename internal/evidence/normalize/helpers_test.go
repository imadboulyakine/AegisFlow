package normalize

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestSeverityFromScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		score float64
		want  evidence.Severity
	}{
		{10, evidence.SeverityCritical}, {9, evidence.SeverityCritical}, {8.9, evidence.SeverityHigh},
		{7, evidence.SeverityHigh}, {6.9, evidence.SeverityMedium}, {4, evidence.SeverityMedium},
		{3.9, evidence.SeverityLow}, {0.1, evidence.SeverityLow}, {0, evidence.SeverityInfo},
		{-1, evidence.SeverityUnknown}, {10.1, evidence.SeverityUnknown}, {math.NaN(), evidence.SeverityUnknown},
	}
	for _, tt := range tests {
		if got := SeverityFromScore(tt.score); got != tt.want {
			t.Errorf("SeverityFromScore(%v) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestNormalizeCVSSVersion(t *testing.T) {
	t.Parallel()
	tests := []struct{ v, vector, want string }{
		{"3.1", "", "3.1"}, {"v3", "", "3.0"}, {"2", "", "2.0"}, {"4", "", "4.0"}, {"V4.0", "", "4.0"},
		{"", "CVSS:3.1/AV:N", "3.1"}, {"", "CVSS:4.0/AV:N", "4.0"}, {"", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "2.0"},
		{"", "", ""}, {"5.0", "", ""}, {"", "CVSS:9/AV:N", ""},
	}
	for _, tt := range tests {
		if got := normalizeCVSSVersion(tt.v, tt.vector); got != tt.want {
			t.Errorf("normalizeCVSSVersion(%q, %q) = %q, want %q", tt.v, tt.vector, got, tt.want)
		}
	}
	if _, ok := newCVSS("3.1", "", math.NaN()); ok {
		t.Error("NaN score accepted")
	}
}

func TestNormalizeDigest(t *testing.T) {
	t.Parallel()
	h64 := strings.Repeat("a", 64)
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"sha256:" + h64, "sha256:" + h64, true},
		{"SHA256:" + strings.ToUpper(h64), "sha256:" + h64, true},
		{"sha256%3A" + h64, "sha256:" + h64, true},
		{"sha-256:" + h64, "sha256:" + h64, true},
		{"sha256-" + h64, "sha256:" + h64, true},
		{"sha384:" + strings.Repeat("b", 96), "sha384:" + strings.Repeat("b", 96), true},
		{"sha256:" + h64[:63], "", false},
		{"sha256:" + h64[:63] + "g", "", false},
		{"md5:" + strings.Repeat("a", 32), "", false},
		{h64, "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := normalizeDigest(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("normalizeDigest(%q) = %q, %v", tt.in, got, ok)
		}
	}
	if _, ok := digestFromOCIPURL("pkg:npm/a@sha256:" + h64); ok {
		t.Error("non-oci purl yielded a digest")
	}
	if _, ok := digestFromOCIPURL("pkg:oci/app"); ok {
		t.Error("oci purl without version yielded a digest")
	}
	if _, ok := digestFromOCIPURL("pkg:oci/app@%zz"); ok {
		t.Error("bad escape yielded a digest")
	}
	if d, ok := digestFromReference("ghcr.io/a/b@sha256:" + h64); !ok || d != "sha256:"+h64 {
		t.Errorf("digestFromReference = %q %v", d, ok)
	}
	if isHex("") {
		t.Error("empty string is not hex")
	}
}

func TestCanonicalVulnID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		primary string
		aliases []string
		id      string
		rest    []string
	}{
		{"GO-2022-1059", []string{"CVE-2022-32149", "GHSA-x"}, "CVE-2022-32149", []string{"GO-2022-1059", "GHSA-x"}},
		{"cve-2020-1", nil, "CVE-2020-1", nil},
		{"GHSA-x", []string{"", " GHSA-x ", "GHSA-y"}, "GHSA-x", []string{"GHSA-y"}},
		{"", []string{"CVE-1"}, "CVE-1", nil},
		{"", nil, "", nil},
		{"CVE-1", []string{"CVE-2"}, "CVE-1", []string{"CVE-2"}},
	}
	for _, tt := range tests {
		id, rest := canonicalVulnID(tt.primary, tt.aliases)
		if id != tt.id || !reflect.DeepEqual(rest, tt.rest) {
			t.Errorf("canonicalVulnID(%q, %v) = %q, %v; want %q, %v", tt.primary, tt.aliases, id, rest, tt.id, tt.rest)
		}
	}
}

func TestVulnIDFromIRI(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"https://pkg.go.dev/vuln/GO-2022-1059", "GO-2022-1059"},
		{"https://nvd.nist.gov/vuln/detail/CVE-2022-32149", "CVE-2022-32149"},
		{"https://github.com/advisories/GHSA-69ch-w2m2-3vjp", "GHSA-69ch-w2m2-3vjp"},
		{"https://example.com/advisories/", "https://example.com/advisories/"},
		{"https://example.com/my-page", "https://example.com/my-page"},
		{"https://example.com/V2-thing", "https://example.com/V2-thing"},
		{"urn:cve:CVE-1", "urn:cve:CVE-1"},
		{"CVE-2020-1", "CVE-2020-1"},
		{"http://[::1", "http://[::1"},
	}
	for _, tt := range tests {
		if got := vulnIDFromIRI(tt.in); got != tt.want {
			t.Errorf("vulnIDFromIRI(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClip(t *testing.T) {
	t.Parallel()
	if clip("short", 10) != "short" {
		t.Error("short strings must be unchanged")
	}
	s := strings.Repeat("é", 100) // 2 bytes per rune
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 50, 199} {
		got := clip(s, n)
		if !utf8.ValidString(got) || !strings.HasSuffix(got, "…") || len(got) > max(n, len("…")) {
			t.Errorf("clip(_, %d) = %q (len %d)", n, got, len(got))
		}
	}
}

func TestFlexFloat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in  string
		val float64
		set bool
	}{
		{`7.5`, 7.5, true}, {`"7.5"`, 7.5, true}, {`" 9 "`, 9, true}, {`"high"`, 0, false},
		{`"NaN"`, 0, false}, {`"Inf"`, 0, false}, {`null`, 0, false}, {`true`, 0, false}, {`1e400`, 0, false},
	}
	for _, tt := range tests {
		var f flexFloat
		if err := json.Unmarshal([]byte(tt.in), &f); err != nil {
			t.Errorf("%s: %v", tt.in, err)
		}
		if f.Value != tt.val || f.Set != tt.set {
			t.Errorf("flexFloat(%s) = %+v", tt.in, f)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	t.Parallel()
	if imageRepository("reg:5000/a/b:1@sha256:x") != "reg:5000/a/b" || imageRepository("reg:5000/a") != "reg:5000/a" {
		t.Error("imageRepository")
	}
	kinds := map[string]evidence.ArtifactKind{
		"container": evidence.ArtifactContainerImage, "SOURCE": evidence.ArtifactSource,
		"OPERATING_SYSTEM": evidence.ArtifactSource, "library": evidence.ArtifactSource, "": evidence.ArtifactSource,
	}
	for typ, want := range kinds {
		if got := artifactKind(typ, false); got != want {
			t.Errorf("artifactKind(%q) = %s, want %s", typ, got, want)
		}
	}
	if artifactKind("archive", true) != evidence.ArtifactBinary {
		t.Error("archive with digest must be binary")
	}
	if firstLine(" \n\n  ") != "" || firstNonEmpty("", "") != "" {
		t.Error("empty helpers")
	}
	if vulnTitle("CVE-1", nil) != "CVE-1" || vulnTitle("CVE-1", &evidence.Component{Name: "a"}) != "CVE-1 in a" {
		t.Error("vulnTitle")
	}
	if toolList(evidence.Tool{}) != nil {
		t.Error("toolList of empty tool must be nil")
	}
	if validPURL("pkg:npm/a b") || !validPURL("pkg:npm/a") {
		t.Error("validPURL")
	}
	if genericPURL("a/b", "") != "pkg:generic/a%2Fb" {
		t.Errorf("genericPURL = %q", genericPURL("a/b", ""))
	}
	if cleanPath(" ") != "" {
		t.Error("cleanPath blank")
	}
	if purlName("x") != "" || purlVersion("pkg:npm/a") != "" {
		t.Error("purl helpers on invalid input")
	}
	g := newDependencyGraph()
	g.addEdge("", "a")
	g.addEdge("a", "a")
	if len(g.out) != 0 {
		t.Error("self and empty edges must be ignored")
	}
}
