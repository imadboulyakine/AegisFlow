package normalize

import (
	"reflect"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestDedupe(t *testing.T) {
	t.Parallel()
	published := time.Date(2022, 10, 11, 0, 0, 0, 0, time.UTC)
	grype := evidence.Finding{
		Kind:         evidence.FindingVulnerability,
		Fingerprint:  "fp1",
		Title:        "CVE-2022-32149 in golang.org/x/text@v0.3.7",
		Severity:     evidence.SeverityMedium,
		Tools:        []evidence.Tool{{Name: "grype", Version: "0.121.0"}},
		Reachability: evidence.ReachabilityUnknown,
		Vulnerability: &evidence.Vulnerability{
			ID: "CVE-2022-32149", Aliases: []string{"GHSA-69ch-w2m2-3vjp"},
			CVSS:     []evidence.CVSS{{Version: "3.1", Vector: "v", BaseScore: 7.5}},
			Severity: evidence.SeverityMedium,
		},
		FixedVersions: []string{"0.3.8"},
	}
	govuln := evidence.Finding{
		Kind:         evidence.FindingVulnerability,
		Fingerprint:  "fp1",
		Message:      "Denial of service",
		Severity:     evidence.SeverityHigh,
		RuleID:       "GO-2022-1059",
		Tools:        []evidence.Tool{{Name: "govulncheck", Version: "v1.9.0"}, {Name: "grype", Version: "0.121.0"}},
		Reachability: evidence.ReachabilityCalled,
		Component:    &evidence.Component{PURL: "pkg:golang/golang.org/x/text@v0.3.7", Licenses: []string{"BSD-3-Clause"}},
		Location:     &evidence.Location{Path: "go.mod"},
		Vulnerability: &evidence.Vulnerability{
			ID: "GO-2022-1059", Aliases: []string{"CVE-2022-32149", "GHSA-69ch-w2m2-3vjp"},
			CVSS:      []evidence.CVSS{{Version: "3.1", Vector: "v", BaseScore: 7.5}, {Version: "4.0", Vector: "w", BaseScore: 8}},
			CWEs:      []string{"CWE-772"},
			Summary:   "DoS",
			Severity:  evidence.SeverityHigh,
			Published: published,
		},
		FixedVersions: []string{"v0.3.8", "0.3.8"},
	}
	other := evidence.Finding{Kind: evidence.FindingCode, Fingerprint: "fp2", Title: "other"}
	noFP := evidence.Finding{Kind: evidence.FindingCode, Title: "no fingerprint"}

	in := []evidence.Finding{grype, other, noFP, govuln, noFP}
	snapshot := cloneAll(in)
	out := Dedupe(in)

	if !reflect.DeepEqual(in, snapshot) {
		t.Fatal("Dedupe modified its input")
	}
	if len(out) != 4 {
		t.Fatalf("len(out) = %d, want 4 (merged pair, other, two unfingerprinted)", len(out))
	}
	m := out[0]
	if m.Severity != evidence.SeverityHigh || m.Reachability != evidence.ReachabilityCalled {
		t.Errorf("severity/reachability not maximized: %s/%s", m.Severity, m.Reachability)
	}
	wantTools := []evidence.Tool{{Name: "grype", Version: "0.121.0"}, {Name: "govulncheck", Version: "v1.9.0"}}
	if !reflect.DeepEqual(m.Tools, wantTools) {
		t.Errorf("tools = %+v, want %+v", m.Tools, wantTools)
	}
	if !reflect.DeepEqual(m.FixedVersions, []string{"0.3.8", "v0.3.8"}) {
		t.Errorf("fixed versions = %v", m.FixedVersions)
	}
	if m.Title != grype.Title || m.Message != "Denial of service" || m.RuleID != "GO-2022-1059" {
		t.Errorf("empty fields not filled from duplicates: %+v", m)
	}
	if m.Component == nil || m.Location == nil {
		t.Error("component/location not taken from duplicate")
	}
	v := m.Vulnerability
	if v.ID != "CVE-2022-32149" || !reflect.DeepEqual(v.Aliases, []string{"GHSA-69ch-w2m2-3vjp", "GO-2022-1059"}) {
		t.Errorf("vulnerability ids = %s %v", v.ID, v.Aliases)
	}
	if len(v.CVSS) != 2 || !reflect.DeepEqual(v.CWEs, []string{"CWE-772"}) || v.Summary != "DoS" ||
		v.Severity != evidence.SeverityHigh || !v.Published.Equal(published) {
		t.Errorf("vulnerability not merged: %+v", v)
	}
	// Mutating the output must not affect the input.
	out[0].Vulnerability.Aliases[0] = "mutated"
	out[0].Component.Licenses[0] = "mutated"
	if in[0].Vulnerability.Aliases[0] != "GHSA-69ch-w2m2-3vjp" || in[3].Component.Licenses[0] != "BSD-3-Clause" {
		t.Error("output aliases input slices")
	}
}

func TestDedupeFillsMissingParts(t *testing.T) {
	t.Parallel()
	a := evidence.Finding{Fingerprint: "x"}
	b := evidence.Finding{
		Fingerprint:   "x",
		Kind:          evidence.FindingSecret,
		Vulnerability: &evidence.Vulnerability{ID: "CVE-1"},
	}
	out := Dedupe([]evidence.Finding{a, b})
	if len(out) != 1 || out[0].Kind != evidence.FindingSecret || out[0].Vulnerability == nil || out[0].Vulnerability.ID != "CVE-1" {
		t.Fatalf("missing parts not filled: %+v", out)
	}
	if Dedupe(nil) != nil {
		t.Error("Dedupe(nil) must be nil")
	}
	if got := Dedupe([]evidence.Finding{}); got == nil || len(got) != 0 {
		t.Error("Dedupe(empty) must be empty, not nil")
	}
}

func TestReachabilityRank(t *testing.T) {
	t.Parallel()
	order := []evidence.Reachability{"", evidence.ReachabilityUnknown, evidence.ReachabilityImported, evidence.ReachabilityCalled}
	for i := 1; i < len(order); i++ {
		if reachabilityRank(order[i]) <= reachabilityRank(order[i-1]) {
			t.Errorf("%q must rank above %q", order[i], order[i-1])
		}
	}
}

func cloneAll(in []evidence.Finding) []evidence.Finding {
	out := make([]evidence.Finding, len(in))
	for i := range in {
		out[i] = cloneFinding(&in[i])
	}
	return out
}
