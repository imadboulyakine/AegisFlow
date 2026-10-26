package normalize

import (
	"errors"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestSPDXFixtures(t *testing.T) {
	t.Parallel()
	dir := parseFixture(t, "spdx-2.3-syft-dir.json")
	if dir.Tool != (evidence.Tool{Name: "syft", Version: "1.55.0"}) || dir.FormatVersion != "2.3" {
		t.Errorf("tool/version = %+v %q", dir.Tool, dir.FormatVersion)
	}
	if dir.Subject == nil || dir.Subject.Kind != evidence.ArtifactSource || dir.Subject.Name != "example.com/vulnapp" {
		t.Errorf("subject = %+v", dir.Subject)
	}
	if len(dir.Components) != 3 || !dir.Components[1].Direct || !dir.Components[2].Direct || dir.Components[0].Direct {
		t.Errorf("components = %+v", dir.Components)
	}

	img := parseFixture(t, "spdx-2.3-syft-image.json")
	want := evidence.Artifact{
		Kind:   evidence.ArtifactContainerImage,
		Name:   "gcr.io/distroless/static-debian13",
		Digest: "sha256:433bb346cd0b6b8346462f879adaa4ac0fbb463a72901b46736ede4aeca3dadc",
	}
	if img.Subject == nil || *img.Subject != want {
		t.Errorf("image subject = %+v, want %+v", img.Subject, want)
	}
	for _, c := range img.Components {
		if c.Ecosystem != "deb" || len(c.Licenses) == 0 {
			t.Errorf("image component = %+v", c)
		}
	}
}

func TestSPDXEdgeCases(t *testing.T) {
	t.Parallel()
	doc := mustParse(t, evidence.FormatSPDX, `{"spdxVersion":"SPDX-2.2","SPDXID":"SPDXRef-DOCUMENT",
		"creationInfo":{"creators":["Organization: Acme","Tool: sbom-tool-v2.1.0","Tool: other-1"]},
		"documentDescribes":["SPDXRef-missing"],
		"packages":[
		  {"SPDXID":"SPDXRef-root","name":"app","versionInfo":"1.0","primaryPackagePurpose":"FILE",
		   "checksums":[{"algorithm":"SHA512","checksumValue":"`+repeatHex("c", 128)+`"}]},
		  {"SPDXID":"SPDXRef-a","name":"a","versionInfo":"NOASSERTION","licenseConcluded":"NONE","licenseDeclared":"MIT",
		   "externalRefs":[{"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a"},
		   {"referenceCategory":"PACKAGE_MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/a"}]},
		  {"SPDXID":"SPDXRef-b","name":"b","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/b@2"}]},
		  {"SPDXID":"SPDXRef-c","name":"c","licenseConcluded":"NOASSERTION"}
		],
		"relationships":[
		  {"spdxElementId":"SPDXRef-root","relatedSpdxElement":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBED_BY"},
		  {"spdxElementId":"SPDXRef-root","relatedSpdxElement":"SPDXRef-a","relationshipType":"DEPENDS_ON"},
		  {"spdxElementId":"SPDXRef-root","relatedSpdxElement":"SPDXRef-b","relationshipType":"DEPENDENCY_MANIFEST_OF"}
		]}`)
	if doc.Tool != (evidence.Tool{Name: "sbom-tool", Version: "v2.1.0"}) || doc.FormatVersion != "2.2" {
		t.Errorf("tool = %+v %q", doc.Tool, doc.FormatVersion)
	}
	if doc.Subject.Kind != evidence.ArtifactBinary || doc.Subject.Digest != "sha512:"+repeatHex("c", 128) {
		t.Errorf("subject = %+v", doc.Subject)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("components = %+v", doc.Components)
	}
	a, b := doc.Components[0], doc.Components[1]
	if a.Version != "" || !a.Direct || len(a.Licenses) != 1 || a.Licenses[0] != "MIT" {
		t.Errorf("a = %+v", a)
	}
	if b.Direct {
		t.Errorf("DEPENDENCY_MANIFEST_OF is not a dependency edge: %+v", b)
	}

	for _, tc := range []struct {
		creators []string
		want     evidence.Tool
	}{
		{[]string{"Tool: trivy"}, evidence.Tool{Name: "trivy"}},
		{[]string{"Tool: my-tool-name"}, evidence.Tool{Name: "my-tool-name"}},
		{[]string{"Tool: x-1.2-beta"}, evidence.Tool{Name: "x", Version: "1.2-beta"}},
		{[]string{"Tool:   ", "Person: Jane"}, evidence.Tool{}},
		{nil, evidence.Tool{}},
	} {
		if got := spdxTool(tc.creators); got != tc.want {
			t.Errorf("spdxTool(%q) = %+v, want %+v", tc.creators, got, tc.want)
		}
	}

	errCases := []struct {
		name, input string
		want        error
	}{
		{"spdx 3", `{"spdxVersion":"SPDX-3.0","SPDXID":"SPDXRef-DOCUMENT"}`, ErrUnsupportedVersion},
		{"bad document id", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-X"}`, ErrInvalid},
		{"package without name", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"SPDXRef-a"}]}`, ErrInvalid},
		{"packages not array", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":{}}`, ErrInvalid},
	}
	for _, tc := range errCases {
		if _, err := parseString(t, evidence.FormatSPDX, tc.input); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func repeatHex(s string, n int) string {
	return strings.Repeat(s, n)
}
