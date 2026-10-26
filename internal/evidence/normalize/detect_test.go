package normalize

import (
	"errors"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestDetect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  evidence.Format
	}{
		{"cyclonedx", `{"bomFormat":"CycloneDX","specVersion":"1.6"}`, evidence.FormatCycloneDX},
		{"spdx", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`, evidence.FormatSPDX},
		{"spdx3 still detected as spdx", `{"spdxVersion":"SPDX-3.0"}`, evidence.FormatSPDX},
		{"openvex", `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`, evidence.FormatOpenVEX},
		{"sarif version", `{"version":"2.1.0","runs":[]}`, evidence.FormatSARIF},
		{"sarif schema only", `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[]}`, evidence.FormatSARIF},
		{"grype", `{"matches":[],"source":{},"descriptor":{"name":"grype"}}`, evidence.FormatGrype},
		{"govulncheck config", `{"config":{"protocol_version":"v1.0.0"}}` + "\n" + `{"progress":{}}`, evidence.FormatGovulncheck},
		{"govulncheck progress first", `{"progress":{"message":"x"}}`, evidence.FormatGovulncheck},
		{"govulncheck SBOM first", `{"SBOM":{"roots":[]}}`, evidence.FormatGovulncheck},
		{"leading whitespace and BOM", "\xEF\xBB\xBF \n\t" + `{"bomFormat":"CycloneDX"}`, evidence.FormatCycloneDX},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Detect([]byte(tt.input))
			if err != nil || got != tt.want {
				t.Fatalf("Detect = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestDetectUnknown(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"array", `[{"bomFormat":"CycloneDX"}]`},
		{"scalar", `"CycloneDX"`},
		{"xml cyclonedx", `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>`},
		{"spdx tag-value", "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n"},
		{"malformed", `{"bomFormat":`},
		{"null object", `null`},
		{"empty object", `{}`},
		{"case differs", `{"BOMFORMAT":"CycloneDX"}`},
		{"bomFormat not a string", `{"bomFormat":1}`},
		{"runs null", `{"version":"2.1.0","runs":null}`},
		{"runs without version or schema", `{"runs":[]}`},
		{"grype without descriptor", `{"matches":[]}`},
		{"two govulncheck keys", `{"config":{},"finding":{}}`},
		{"other single key", `{"result":{}}`},
		{"openvex other context", `{"@context":"https://example.com/ns"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Detect([]byte(tt.input))
			if !errors.Is(err, ErrUnknownFormat) || got != "" {
				t.Fatalf("Detect = %q, %v; want ErrUnknownFormat", got, err)
			}
		})
	}
}
