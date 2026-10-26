package normalize

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func parseString(t *testing.T, format evidence.Format, input string) (*evidence.Document, error) {
	t.Helper()
	return ParseBytes(format, []byte(input), Options{})
}

func mustParse(t *testing.T, format evidence.Format, input string) *evidence.Document {
	t.Helper()
	doc, err := parseString(t, format, input)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	checkInvariants(t, doc)
	return doc
}

func TestCycloneDXFixtures(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"cyclonedx-1.4-syft-dir.json", "cyclonedx-1.5-syft-dir.json", "cyclonedx-1.7-syft-dir.json"} {
		doc := parseFixture(t, name)
		if doc.Tool != (evidence.Tool{Name: "syft", Version: "1.55.0"}) {
			t.Errorf("%s: tool = %+v", name, doc.Tool)
		}
		if doc.Subject == nil || doc.Subject.Kind != evidence.ArtifactSource || doc.Subject.Name != "example.com/vulnapp" {
			t.Errorf("%s: subject = %+v", name, doc.Subject)
		}
		direct := map[string]bool{}
		for _, c := range doc.Components {
			direct[c.PURL] = c.Direct
		}
		want := map[string]bool{
			"pkg:golang/example.com/vulnapp":                                 false,
			"pkg:golang/golang.org/x/net@v0.0.0-20220722155237-a158d28d115b": true,
			"pkg:golang/golang.org/x/text@v0.3.7":                            true,
		}
		if !reflect.DeepEqual(direct, want) {
			t.Errorf("%s: direct flags = %v, want %v (file components must be skipped)", name, direct, want)
		}
	}

	img := parseFixture(t, "cyclonedx-1.6-syft-image.json")
	if img.Subject == nil || img.Subject.Kind != evidence.ArtifactContainerImage || img.Subject.Digest != "" {
		t.Errorf("syft image subject = %+v (syft CycloneDX carries no digest)", img.Subject)
	}
	if len(img.Components) != 4 {
		t.Errorf("image components = %d, want 4 deb packages", len(img.Components))
	}

	vdr := parseFixture(t, "cyclonedx-1.6-vdr-handbuilt.json")
	if vdr.Subject.Digest != "sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99" ||
		vdr.Subject.Name != "ghcr.io/imadboulyakine/aegisflow-demo" {
		t.Errorf("vdr subject = %+v", vdr.Subject)
	}
	if vdr.Tool.Name != "trivy" {
		t.Errorf("vdr tool = %+v", vdr.Tool)
	}
	var tarLicenses []string
	for _, c := range vdr.Components {
		if c.Name == "tar" {
			tarLicenses = c.Licenses
		}
	}
	if !reflect.DeepEqual(tarLicenses, []string{"GPL-2.0-only OR GPL-3.0-only", "GPL-3.0-or-later"}) {
		t.Errorf("duplicate components must merge licenses: %v", tarLicenses)
	}
	if len(vdr.Findings) != 3 {
		t.Fatalf("vdr findings = %d, want 3 (exploitable x/text + fixture advisory on 2 packages)", len(vdr.Findings))
	}
	f := vdr.Findings[0]
	if f.Vulnerability.ID != "CVE-2022-32149" || f.Severity != evidence.SeverityHigh || len(f.Vulnerability.CVSS) != 1 ||
		!reflect.DeepEqual(f.Vulnerability.CWEs, []string{"CWE-772"}) || f.Vulnerability.Published.IsZero() {
		t.Errorf("x/text finding = %+v / %+v", f, f.Vulnerability)
	}
	if vdr.Findings[1].Severity != evidence.SeverityMedium || vdr.Findings[1].Vulnerability.CVSS[0].Version != "4.0" {
		t.Errorf("severity must come from the CVSS v4 score when no qualitative severity: %+v", vdr.Findings[1])
	}
	if vdr.Findings[2].Component.PURL != "pkg:npm/%40fixture/unlisted@1.2.3" || vdr.Findings[2].Component.Name != "@fixture/unlisted" {
		t.Errorf("affects ref that is a PURL outside the BOM: %+v", vdr.Findings[2].Component)
	}
	if len(vdr.VEX) != 2 || vdr.VEX[0].Status != evidence.VEXAffected || vdr.VEX[1].Status != evidence.VEXNotAffected ||
		vdr.VEX[1].Justification != "code_not_reachable" || vdr.VEX[1].Timestamp.IsZero() {
		t.Errorf("vdr VEX = %+v", vdr.VEX)
	}
}

func TestCycloneDXEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("legacy tools array, services and nested components", func(t *testing.T) {
		t.Parallel()
		doc := mustParse(t, evidence.FormatCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.5",
			"metadata":{"tools":{"services":[{"name":""},{"name":"svc","version":"2"}]},
			  "component":{"bom-ref":"root","type":"application","name":"app","group":"acme"}},
			"components":[{"bom-ref":"a","name":"a","purl":"pkg:npm/a@1",
			  "components":[{"bom-ref":"b","name":"b","group":"@s","purl":"pkg:npm/%40s/b@2"}]}],
			"dependencies":[{"ref":"root","dependsOn":["b"]},{"ref":"a","dependsOn":["b"]}]}`)
		if doc.Tool != (evidence.Tool{Name: "svc", Version: "2"}) {
			t.Errorf("tool = %+v", doc.Tool)
		}
		if doc.Subject.Name != "acme/app" || doc.Subject.Kind != evidence.ArtifactSource {
			t.Errorf("subject = %+v", doc.Subject)
		}
		if len(doc.Components) != 2 || doc.Components[1].Name != "@s/b" || !doc.Components[1].Direct || doc.Components[0].Direct {
			t.Errorf("components = %+v", doc.Components)
		}
	})

	t.Run("file subject digest from hashes and digest property", func(t *testing.T) {
		t.Parallel()
		doc := mustParse(t, evidence.FormatCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.4",
			"metadata":{"tools":[{"vendor":"v","name":"cdxgen","version":"10"}],
			  "component":{"type":"file","name":"bin/app","hashes":[{"alg":"MD5","content":"00"},
			  {"alg":"SHA-256","content":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}}}`)
		if doc.Subject.Kind != evidence.ArtifactBinary || doc.Subject.Digest != "sha256:"+strings.Repeat("a", 64) {
			t.Errorf("subject = %+v", doc.Subject)
		}
		doc = mustParse(t, evidence.FormatCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.6",
			"metadata":{"component":{"type":"container","name":"registry:5000/team/app:1.2",
			  "properties":[{"name":"syft:image:manifestDigest","value":"sha256:`+strings.Repeat("b", 64)+`"}]}}}`)
		if doc.Subject.Digest != "sha256:"+strings.Repeat("b", 64) || doc.Subject.Name != "registry:5000/team/app" {
			t.Errorf("subject = %+v", doc.Subject)
		}
	})

	t.Run("vulnerability states", func(t *testing.T) {
		t.Parallel()
		doc := mustParse(t, evidence.FormatCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.6",
			"components":[{"bom-ref":"c","name":"c","version":"1","purl":"pkg:npm/c@1"},{"bom-ref":"nopurl","name":"np","version":"3"}],
			"vulnerabilities":[
			  {"id":"CVE-2020-0001","affects":[{"ref":"c"}],"analysis":{"state":"resolved","lastUpdated":"bad"},"updated":"2024-01-02T03:04:05Z"},
			  {"id":"CVE-2020-0002","affects":[{"ref":"c"},{"ref":""}],"analysis":{"state":"false_positive"}},
			  {"id":"CVE-2020-0003","affects":[{"ref":"nopurl"}],"analysis":{"state":"in_triage"},
			   "ratings":[{"score":99,"method":"CVSSv31"},{"score":3.1,"method":"OWASP","severity":"low"}],"cwes":[0,79]},
			  {"id":"GHSA-aaaa-bbbb-cccc","references":[{"id":"cve-2020-0004"}],"detail":"\n first line \nsecond","affects":[{"ref":"c"}]}
			]}`)
		if len(doc.Findings) != 2 {
			t.Fatalf("findings = %+v", doc.Findings)
		}
		triage := doc.Findings[0]
		if triage.Component.PURL != "pkg:generic/np@3" || triage.Severity != evidence.SeverityLow ||
			len(triage.Vulnerability.CVSS) != 0 || !reflect.DeepEqual(triage.Vulnerability.CWEs, []string{"CWE-79"}) {
			t.Errorf("in_triage finding = %+v %+v", triage, triage.Vulnerability)
		}
		ghsa := doc.Findings[1]
		if ghsa.Vulnerability.ID != "CVE-2020-0004" || ghsa.Vulnerability.Aliases[0] != "GHSA-aaaa-bbbb-cccc" ||
			ghsa.Vulnerability.Summary != "first line" || ghsa.RuleID != "GHSA-aaaa-bbbb-cccc" ||
			ghsa.Severity != evidence.SeverityUnknown {
			t.Errorf("GHSA finding = %+v %+v", ghsa, ghsa.Vulnerability)
		}
		if len(doc.VEX) != 3 {
			t.Fatalf("vex = %+v", doc.VEX)
		}
		if doc.VEX[0].Status != evidence.VEXFixed || doc.VEX[0].Timestamp.Year() != 2024 {
			t.Errorf("resolved → fixed with updated timestamp: %+v", doc.VEX[0])
		}
		if doc.VEX[1].Status != evidence.VEXNotAffected || doc.VEX[1].Justification != "false_positive" {
			t.Errorf("false_positive: %+v", doc.VEX[1])
		}
		if doc.VEX[2].Status != evidence.VEXUnderInvestigation || doc.VEX[2].Products[0] != "pkg:generic/np@3" {
			t.Errorf("in_triage: %+v", doc.VEX[2])
		}
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name, input string
			want        error
		}{
			{"wrong bomFormat", `{"bomFormat":"cyclonedx","specVersion":"1.6"}`, ErrInvalid},
			{"spec 1.3", `{"bomFormat":"CycloneDX","specVersion":"1.3"}`, ErrUnsupportedVersion},
			{"spec 2.0", `{"bomFormat":"CycloneDX","specVersion":"2.0"}`, ErrUnsupportedVersion},
			{"spec number", `{"bomFormat":"CycloneDX","specVersion":1.6}`, ErrInvalid},
			{"tools string", `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"tools":"syft"}}`, ErrInvalid},
			{"tools bad array", `{"bomFormat":"CycloneDX","specVersion":"1.4","metadata":{"tools":[1]}}`, ErrInvalid},
			{"tools bad object", `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"tools":{"components":"x"}}}`, ErrInvalid},
			{"component without name", `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"purl":"pkg:npm/a@1"}]}`, ErrInvalid},
			{"vulnerability without id", `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":" "}]}`, ErrInvalid},
			{"unknown analysis state", `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","affects":[{"ref":"x"}],"analysis":{"state":"maybe"}}]}`, ErrInvalid},
			{"analysis without affects", `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected"}}]}`, ErrInvalid},
			{"string cwe", `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","cwes":["79"]}]}`, ErrInvalid},
		}
		for _, tt := range tests {
			if _, err := parseString(t, evidence.FormatCycloneDX, tt.input); !errors.Is(err, tt.want) {
				t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
			}
		}
	})
}
