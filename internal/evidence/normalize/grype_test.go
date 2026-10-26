package normalize

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestGrypeFixture(t *testing.T) {
	t.Parallel()
	doc := parseFixture(t, "grype-image-handbuilt.json")
	if doc.Tool != (evidence.Tool{Name: "grype", Version: "0.121.0"}) {
		t.Errorf("tool = %+v", doc.Tool)
	}
	// Digest priority: user input (none) → repoDigests (index digest) → manifestDigest.
	want := evidence.Artifact{
		Kind:   evidence.ArtifactContainerImage,
		Name:   "ghcr.io/imadboulyakine/aegisflow-demo",
		Digest: "sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99",
	}
	if *doc.Subject != want {
		t.Errorf("subject = %+v", doc.Subject)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (two x/text locations merged, ignoredMatches skipped)", len(doc.Findings))
	}
	text := doc.Findings[0]
	if text.Vulnerability.ID != "CVE-2022-32149" || !reflect.DeepEqual(text.Vulnerability.Aliases, []string{"GHSA-69ch-w2m2-3vjp"}) ||
		text.RuleID != "GHSA-69ch-w2m2-3vjp" || text.Severity != evidence.SeverityHigh ||
		!reflect.DeepEqual(text.FixedVersions, []string{"0.3.8"}) || text.Reachability != evidence.ReachabilityUnknown ||
		!reflect.DeepEqual(text.Vulnerability.CWEs, []string{"CWE-772"}) {
		t.Errorf("x/text finding = %+v %+v", text, text.Vulnerability)
	}
	tar := doc.Findings[1]
	if tar.Severity != evidence.SeverityInfo || len(tar.Vulnerability.CVSS) != 1 || tar.Vulnerability.CVSS[0].Version != "2.0" ||
		tar.Vulnerability.CVSS[0].BaseScore != 10 || tar.Component.Ecosystem != "deb" {
		t.Errorf("tar finding (Negligible kept, CVSS from related record) = %+v %+v", tar, tar.Vulnerability)
	}
	// Cross-tool: Grype and govulncheck report the same advisory on the same package with the
	// same fingerprint, so the ingest pipeline can merge them.
	gv := parseFixture(t, "govulncheck-source.json")
	var found bool
	for _, f := range gv.Findings {
		if f.Fingerprint == text.Fingerprint {
			found = true
			merged := Dedupe([]evidence.Finding{text, f})
			if len(merged) != 1 || len(merged[0].Tools) != 2 || merged[0].Reachability != evidence.ReachabilityCalled {
				t.Errorf("cross-tool merge = %+v", merged)
			}
		}
	}
	if !found {
		t.Error("grype and govulncheck fingerprints for CVE-2022-32149 on x/text differ")
	}
}

func TestGrypeEdgeCases(t *testing.T) {
	t.Parallel()
	doc := mustParse(t, evidence.FormatGrype, `{"descriptor":{"name":"grype"},"source":{"type":"directory","target":"/src"},
		"matches":[{"vulnerability":{"id":"GHSA-x","severity":"Unknown","cvss":[{"version":"3.1","vector":"CVSS:3.1/AV:N","metrics":{"baseScore":5.0}},
		  {"version":"9","metrics":{"baseScore":1}},{"version":"3.0"}]},
		  "artifact":{"name":"left pad","version":"1.0","licenses":[{"value":"MIT"},{"spdxExpression":"Apache-2.0"},"ISC",7]}}]}`)
	if *doc.Subject != (evidence.Artifact{Kind: evidence.ArtifactSource, Name: "/src"}) {
		t.Errorf("subject = %+v", doc.Subject)
	}
	f := doc.Findings[0]
	if f.Severity != evidence.SeverityMedium || len(f.Vulnerability.CVSS) != 1 {
		t.Errorf("unknown severity must come from CVSS: %+v %+v", f, f.Vulnerability)
	}
	if f.Component.PURL != "pkg:generic/left%20pad@1.0" || !reflect.DeepEqual(f.Component.Licenses, []string{"MIT", "Apache-2.0", "ISC"}) {
		t.Errorf("component = %+v", f.Component)
	}

	for _, tc := range []struct {
		typ, target string
		want        *evidence.Artifact
	}{
		{"file", `"/bin/app"`, &evidence.Artifact{Kind: evidence.ArtifactBinary, Name: "/bin/app"}},
		{"directory", `{"path":"/repo"}`, &evidence.Artifact{Kind: evidence.ArtifactSource, Name: "/repo"}},
		{"image", `{"userInput":"app:1@sha256:` + strings64("d") + `","manifestDigest":"sha256:` + strings64("e") + `"}`,
			&evidence.Artifact{Kind: evidence.ArtifactContainerImage, Name: "app", Digest: "sha256:" + strings64("d")}},
		{"image", `{"tags":["reg:5000/app:2"],"manifestDigest":"sha256:` + strings64("e") + `"}`,
			&evidence.Artifact{Kind: evidence.ArtifactContainerImage, Name: "reg:5000/app", Digest: "sha256:" + strings64("e")}},
		{"image", `{"userInput":"app:latest"}`, &evidence.Artifact{Kind: evidence.ArtifactContainerImage, Name: "app"}},
		{"sbom", `"x.json"`, nil},
		{"image", `null`, nil},
	} {
		got, err := grypeSubject(tc.typ, []byte(tc.target))
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("grypeSubject(%s, %s) = %+v, %v; want %+v", tc.typ, tc.target, got, err, tc.want)
		}
	}

	errCases := []struct {
		name, input string
		want        error
	}{
		{"no matches", `{"descriptor":{"name":"grype"}}`, ErrInvalid},
		{"no descriptor name", `{"matches":[],"descriptor":{}}`, ErrInvalid},
		{"match without id", `{"matches":[{"artifact":{"name":"a"}}],"descriptor":{"name":"grype"}}`, ErrInvalid},
		{"match without artifact name", `{"matches":[{"vulnerability":{"id":"CVE-1"}}],"descriptor":{"name":"grype"}}`, ErrInvalid},
		{"bad target", `{"matches":[],"descriptor":{"name":"grype"},"source":{"type":"image","target":7}}`, ErrInvalid},
		{"bad target object", `{"matches":[],"descriptor":{"name":"grype"},"source":{"type":"image","target":{"tags":"x"}}}`, ErrInvalid},
		{"bad target string", `{"matches":[],"descriptor":{"name":"grype"},"source":{"type":"file","target":"\ud800"}}`, nil},
	}
	for _, tc := range errCases {
		_, err := parseString(t, evidence.FormatGrype, tc.input)
		if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func strings64(c string) string {
	return strings.Repeat(c, 64)
}
