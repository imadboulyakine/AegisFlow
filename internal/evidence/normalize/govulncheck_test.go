package normalize

import (
	"errors"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestGovulncheckFixture(t *testing.T) {
	t.Parallel()
	doc := parseFixture(t, "govulncheck-source.json")
	if doc.Tool != (evidence.Tool{Name: "govulncheck", Version: "v1.9.0"}) || doc.FormatVersion != "v1.0.0" {
		t.Errorf("tool = %+v %q", doc.Tool, doc.FormatVersion)
	}
	if *doc.Subject != (evidence.Artifact{Kind: evidence.ArtifactSource, Name: "example.com/vulnapp"}) {
		t.Errorf("subject = %+v", doc.Subject)
	}
	if len(doc.Components) != 3 {
		t.Errorf("components = %+v (root module excluded)", doc.Components)
	}
	byRule := map[string]evidence.Finding{}
	for _, f := range doc.Findings {
		byRule[f.RuleID] = f
	}
	if len(doc.Findings) != 3 {
		t.Fatalf("findings = %d, want 3 (one per OSV x module; duplicate OSV message tolerated)", len(doc.Findings))
	}
	tests := []struct {
		osv, id string
		reach   evidence.Reachability
		purl    string
		fixed   string
	}{
		{"GO-2022-1059", "CVE-2022-32149", evidence.ReachabilityCalled, "pkg:golang/golang.org/x/text@v0.3.7", "v0.3.8"},
		{"GO-2026-5029", "CVE-2026-25681", evidence.ReachabilityImported, "pkg:golang/golang.org/x/net@v0.0.0-20220722155237-a158d28d115b", "v0.55.0"},
		{"GO-2023-2102", "CVE-2023-39325", evidence.ReachabilityImported, "pkg:golang/golang.org/x/net@v0.0.0-20220722155237-a158d28d115b", "v0.17.0"},
	}
	for _, tt := range tests {
		f, ok := byRule[tt.osv]
		if !ok {
			t.Errorf("%s missing", tt.osv)
			continue
		}
		if f.Vulnerability.ID != tt.id || f.Reachability != tt.reach || f.Component.PURL != tt.purl ||
			len(f.FixedVersions) != 1 || f.FixedVersions[0] != tt.fixed || f.Severity != evidence.SeverityUnknown ||
			f.Vulnerability.Summary == "" || f.Vulnerability.Published.IsZero() {
			t.Errorf("%s = %+v %+v", tt.osv, f, f.Vulnerability)
		}
	}
}

func TestGovulncheckEdgeCases(t *testing.T) {
	t.Parallel()
	cfg := func(level, mode string) string {
		return `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.1.0","scan_level":"` +
			level + `","scan_mode":"` + mode + `"}}`
	}
	stream := `{"SBOM":{"modules":[{"path":"app"},{"path":"m","version":"v1.0.0"},{"path":""}],"roots":["app","app2"]}}
		{"osv":{"id":"GO-1","aliases":["GHSA-1"],"details":"\nDetails line\n","published":"nope","database_specific":{"cwe_ids":["CWE-1"]}}}
		{"finding":{"osv":"GO-1","fixed_version":"v1.1.0","trace":[{"module":"m","version":"v1.0.0","package":"m/p"}]}}
		{"finding":{"osv":"GO-2","trace":[{"module":"m","version":"v1.0.0"}]}}
		{"progress":{"message":"x"}}`

	doc := mustParse(t, evidence.FormatGovulncheck, cfg("package", "binary")+stream)
	if doc.Subject.Kind != evidence.ArtifactBinary || doc.Subject.Name != "app" {
		t.Errorf("binary subject = %+v", doc.Subject)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("findings = %+v", doc.Findings)
	}
	f1, f2 := doc.Findings[0], doc.Findings[1]
	if f1.Reachability != evidence.ReachabilityUnknown || f1.Vulnerability.ID != "GO-1" || f1.Vulnerability.Summary != "Details line" ||
		!f1.Vulnerability.Published.IsZero() || len(f1.Vulnerability.CWEs) != 1 {
		t.Errorf("package-level scan finding = %+v %+v", f1, f1.Vulnerability)
	}
	if f2.Vulnerability.ID != "GO-2" || f2.Vulnerability.Summary != "" || f2.FixedVersions != nil {
		t.Errorf("finding with unknown OSV = %+v %+v", f2, f2.Vulnerability)
	}

	doc = mustParse(t, evidence.FormatGovulncheck, cfg("", "source")+stream)
	if doc.Findings[0].Reachability != evidence.ReachabilityImported || doc.Findings[1].Reachability != evidence.ReachabilityImported {
		t.Errorf("default (symbol) scan level: %+v", doc.Findings)
	}
	doc = mustParse(t, evidence.FormatGovulncheck, `{"config":{"protocol_version":"v1.2.0"}}`)
	if doc.Tool.Name != "govulncheck" || doc.Subject != nil {
		t.Errorf("minimal stream = %+v", doc)
	}

	errCases := []struct {
		name, input string
		want        error
	}{
		{"missing config", `{"progress":{"message":"x"}}`, ErrInvalid},
		{"protocol v2", `{"config":{"protocol_version":"v2.0.0"}}`, ErrUnsupportedVersion},
		{"duplicate config", cfg("symbol", "source") + cfg("symbol", "source"), ErrInvalid},
		{"unknown scan mode", cfg("symbol", "magic"), ErrInvalid},
		{"finding without trace", cfg("symbol", "source") + `{"finding":{"osv":"GO-1","trace":[]}}`, ErrInvalid},
		{"finding without module", cfg("symbol", "source") + `{"finding":{"osv":"GO-1","trace":[{"package":"p"}]}}`, ErrInvalid},
		{"osv without id", cfg("symbol", "source") + `{"osv":{"summary":"x"}}`, ErrInvalid},
		{"non-object message", cfg("symbol", "source") + `[1]`, ErrInvalid},
	}
	for _, tc := range errCases {
		if _, err := parseString(t, evidence.FormatGovulncheck, tc.input); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}
