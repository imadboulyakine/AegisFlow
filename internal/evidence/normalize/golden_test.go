package normalize

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/golden")

// fixtures lists every testdata fixture with its expected detected format.
var fixtures = []struct {
	file   string
	format evidence.Format
}{
	{"cyclonedx-1.4-syft-dir.json", evidence.FormatCycloneDX},
	{"cyclonedx-1.5-syft-dir.json", evidence.FormatCycloneDX},
	{"cyclonedx-1.6-syft-image.json", evidence.FormatCycloneDX},
	{"cyclonedx-1.6-vdr-handbuilt.json", evidence.FormatCycloneDX},
	{"cyclonedx-1.7-syft-dir.json", evidence.FormatCycloneDX},
	{"spdx-2.3-syft-dir.json", evidence.FormatSPDX},
	{"spdx-2.3-syft-image.json", evidence.FormatSPDX},
	{"sarif-gitleaks.json", evidence.FormatSARIF},
	{"sarif-gosec.json", evidence.FormatSARIF},
	{"sarif-zizmor.json", evidence.FormatSARIF},
	{"sarif-trivy-config.json", evidence.FormatSARIF},
	{"grype-image-handbuilt.json", evidence.FormatGrype},
	{"govulncheck-source.json", evidence.FormatGovulncheck},
	{"openvex-govulncheck.json", evidence.FormatOpenVEX},
	{"openvex-handbuilt.json", evidence.FormatOpenVEX},
}

func readFixture(tb testing.TB, name string) []byte {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		tb.Fatalf("read fixture: %v", err)
	}
	return data
}

// parseFixture detects and parses a fixture, failing the test on error.
func parseFixture(tb testing.TB, name string) *evidence.Document {
	tb.Helper()
	doc, err := ParseBytes("", readFixture(tb, name), Options{})
	if err != nil {
		tb.Fatalf("ParseBytes(%s): %v", name, err)
	}
	return doc
}

// TestGolden pins the complete normalized output of every fixture. Run with -update to rewrite
// the golden files after an intended change, and review the diff.
func TestGolden(t *testing.T) {
	t.Parallel()
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			t.Parallel()
			data := readFixture(t, fx.file)
			format, err := Detect(data)
			if err != nil || format != fx.format {
				t.Fatalf("Detect = %q, %v; want %q", format, err, fx.format)
			}
			doc, err := Parse(fx.format, bytes.NewReader(data), Options{})
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(doc); err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := buf.Bytes()
			golden := filepath.Join("testdata", "golden", strings.TrimSuffix(fx.file, ".json")+".golden.json")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden (run with -update to create): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("normalized output differs from %s (run with -update and review the diff)\n got: %s", golden, got)
			}
		})
	}
}

// TestDocumentInvariants checks properties every normalized document must satisfy.
func TestDocumentInvariants(t *testing.T) {
	t.Parallel()
	for _, fx := range fixtures {
		t.Run(fx.file, func(t *testing.T) {
			t.Parallel()
			checkInvariants(t, parseFixture(t, fx.file))
		})
	}
}

// checkInvariants is shared with the fuzz targets.
func checkInvariants(tb testing.TB, doc *evidence.Document) {
	tb.Helper()
	if doc == nil {
		tb.Fatal("nil document")
	}
	seen := map[string]bool{}
	for i, f := range doc.Findings {
		if f.Kind == "" || f.Fingerprint == "" || f.Title == "" {
			tb.Errorf("finding %d: empty kind, fingerprint or title: %+v", i, f)
		}
		if len(f.Fingerprint) != 64 {
			tb.Errorf("finding %d: fingerprint %q is not 64 hex chars", i, f.Fingerprint)
		}
		if seen[f.Fingerprint] {
			tb.Errorf("finding %d: duplicate fingerprint after Dedupe", i)
		}
		seen[f.Fingerprint] = true
		if f.Severity == "" {
			tb.Errorf("finding %d: empty severity", i)
		}
		if f.Kind == evidence.FindingVulnerability && (f.Vulnerability == nil || f.Component == nil) {
			tb.Errorf("finding %d: vulnerability finding without vulnerability or component", i)
		}
		if f.Component != nil && !validPURL(f.Component.PURL) {
			tb.Errorf("finding %d: invalid component purl %q", i, f.Component.PURL)
		}
		if len(f.Title) > maxTitleLen || len(f.Message) > maxMessageLen {
			tb.Errorf("finding %d: title/message not clipped", i)
		}
	}
	purls := map[string]bool{}
	for i, c := range doc.Components {
		if !validPURL(c.PURL) || c.Ecosystem == "" {
			tb.Errorf("component %d: invalid purl/ecosystem %q/%q", i, c.PURL, c.Ecosystem)
		}
		if purls[c.PURL] {
			tb.Errorf("component %d: duplicate purl %q", i, c.PURL)
		}
		purls[c.PURL] = true
	}
	for i, v := range doc.VEX {
		if v.VulnID == "" || len(v.Products) == 0 || v.Status == "" {
			tb.Errorf("vex %d: incomplete statement %+v", i, v)
		}
	}
	if doc.Subject != nil && doc.Subject.Digest != "" {
		if _, ok := normalizeDigest(doc.Subject.Digest); !ok {
			tb.Errorf("subject digest %q is not normalized", doc.Subject.Digest)
		}
	}
}
