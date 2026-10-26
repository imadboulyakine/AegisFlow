package evidence

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEcosystemFromPURL(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"pkg:golang/golang.org/x/text@v0.3.7", "golang"},
		{"pkg:NPM/lodash@4", "npm"},
		{"pkg:deb/debian/tar@1?arch=amd64", "deb"},
		{"pkg:generic/", "generic"},
		{"pkg:npm", ""},
		{"golang/x", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := EcosystemFromPURL(tt.in); got != tt.want {
			t.Errorf("EcosystemFromPURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSeverityRankAndParse(t *testing.T) {
	t.Parallel()
	order := []Severity{SeverityUnknown, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i, s := range order {
		if s.Rank() != i {
			t.Errorf("%s.Rank() = %d, want %d", s, s.Rank(), i)
		}
	}
	if Severity("bogus").Rank() != 0 {
		t.Error("unknown severity must rank 0")
	}
	parse := map[string]Severity{
		"CRITICAL": SeverityCritical, "High": SeverityHigh, "error": SeverityHigh,
		"Moderate": SeverityMedium, "warning": SeverityMedium, "medium": SeverityMedium, "low": SeverityLow,
		"Negligible": SeverityInfo, "note": SeverityInfo, "none": SeverityInfo, "informational": SeverityInfo,
		"info": SeverityInfo, "": SeverityUnknown, "Unknown": SeverityUnknown, "severe": SeverityUnknown,
	}
	if ParseSeverity(" High ") != SeverityHigh {
		t.Error("ParseSeverity must trim whitespace")
	}
	for in, want := range parse {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestVulnerabilityCVEs(t *testing.T) {
	t.Parallel()
	v := Vulnerability{ID: "GO-2022-1059", Aliases: []string{"CVE-2022-32149", "GHSA-x", "CVE-2022-32149", "CVE-2022-1"}}
	if got := v.CVEs(); !reflect.DeepEqual(got, []string{"CVE-2022-32149", "CVE-2022-1"}) {
		t.Errorf("CVEs() = %v", got)
	}
	if (Vulnerability{ID: "GHSA-x"}).CVEs() != nil {
		t.Error("no CVEs must return nil")
	}
	if got := (Vulnerability{ID: "CVE-1", Aliases: []string{"CVE-1"}}).CVEs(); !reflect.DeepEqual(got, []string{"CVE-1"}) {
		t.Errorf("CVEs() = %v", got)
	}
}

func TestDocumentJSONRoundTrip(t *testing.T) {
	t.Parallel()
	doc := Document{
		Format: FormatGrype, Tool: Tool{Name: "grype", Version: "1"},
		Subject:    &Artifact{Kind: ArtifactContainerImage, Name: "app", Digest: "sha256:" + strings.Repeat("a", 64)},
		Components: []Component{{PURL: "pkg:npm/a@1", Name: "a", Ecosystem: "npm", Direct: true}},
		Findings: []Finding{{
			Kind: FindingVulnerability, Fingerprint: "f", Title: "t", Severity: SeverityHigh,
			Tools:         []Tool{{Name: "grype"}},
			Vulnerability: &Vulnerability{ID: "CVE-1", Severity: SeverityHigh, CVSS: []CVSS{{Version: "3.1", BaseScore: 7.5}}},
			Reachability:  ReachabilityCalled,
		}},
		VEX: []VEXStatement{{VulnID: "CVE-1", Products: []string{"pkg:npm/a@1"}, Status: VEXNotAffected,
			Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"published"`) {
		t.Error("zero Published must be omitted (omitzero)")
	}
	var back Document
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc, back) {
		t.Errorf("round trip mismatch:\n%+v\n%+v", doc, back)
	}
}
