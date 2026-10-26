package normalize

import (
	"errors"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// fuzzOptions keeps fuzz iterations fast while still exercising every limit.
var fuzzOptions = Options{MaxBytes: 1 << 20, MaxItems: 5000, MaxDepth: 32}

func addFixtureSeeds(f *testing.F, format evidence.Format) {
	f.Helper()
	for _, fx := range fixtures {
		if format == "" || fx.format == format {
			f.Add(readFixture(f, fx.file))
		}
	}
}

// fuzzParse parses data as format and checks that failures are classified and successes satisfy
// the document invariants (and that Dedupe is idempotent).
func fuzzParse(t *testing.T, format evidence.Format, data []byte) {
	t.Helper()
	doc, err := ParseBytes(format, data, fuzzOptions)
	if err != nil {
		if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrUnsupportedVersion) && !errors.Is(err, ErrLimitExceeded) &&
			!errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrUnknownFormat) {
			t.Fatalf("unclassified error: %v", err)
		}
		return
	}
	if format != "" && doc.Format != format {
		t.Fatalf("document format %q, want %q", doc.Format, format)
	}
	checkInvariants(t, doc)
	if again := Dedupe(doc.Findings); len(again) != len(doc.Findings) {
		t.Fatalf("Dedupe not idempotent: %d -> %d", len(doc.Findings), len(again))
	}
}

func FuzzDetect(f *testing.F) {
	addFixtureSeeds(f, "")
	f.Add([]byte(`{"config":{}}`))
	f.Add([]byte(`{"runs":[],"$schema":"SARIF"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		format, err := Detect(data)
		if err != nil {
			if !errors.Is(err, ErrUnknownFormat) || format != "" {
				t.Fatalf("Detect = %q, %v", format, err)
			}
			return
		}
		if _, ok := parsers[format]; !ok {
			t.Fatalf("Detect returned unsupported format %q", format)
		}
		fuzzParse(t, "", data)
	})
}

func FuzzParseCycloneDX(f *testing.F) {
	addFixtureSeeds(f, evidence.FormatCycloneDX)
	f.Fuzz(func(t *testing.T, data []byte) { fuzzParse(t, evidence.FormatCycloneDX, data) })
}

func FuzzParseSPDX(f *testing.F) {
	addFixtureSeeds(f, evidence.FormatSPDX)
	f.Fuzz(func(t *testing.T, data []byte) { fuzzParse(t, evidence.FormatSPDX, data) })
}

func FuzzParseSARIF(f *testing.F) {
	addFixtureSeeds(f, evidence.FormatSARIF)
	f.Fuzz(func(t *testing.T, data []byte) { fuzzParse(t, evidence.FormatSARIF, data) })
}

func FuzzParseGrype(f *testing.F) {
	addFixtureSeeds(f, evidence.FormatGrype)
	f.Fuzz(func(t *testing.T, data []byte) { fuzzParse(t, evidence.FormatGrype, data) })
}

func FuzzParseGovulncheck(f *testing.F) {
	addFixtureSeeds(f, evidence.FormatGovulncheck)
	f.Fuzz(func(t *testing.T, data []byte) { fuzzParse(t, evidence.FormatGovulncheck, data) })
}

func FuzzParseOpenVEX(f *testing.F) {
	addFixtureSeeds(f, evidence.FormatOpenVEX)
	f.Fuzz(func(t *testing.T, data []byte) { fuzzParse(t, evidence.FormatOpenVEX, data) })
}

func FuzzCanonicalPURL(f *testing.F) {
	for _, s := range []string{"pkg:golang/golang.org%2Fx%2Ftext@v0.3.7", "pkg:npm/@a/b@1?x=y#p", "pkg:golang/stdlib@go1.2", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c := CanonicalPURL(s)
		if CanonicalPURL(c) != c && strings.HasPrefix(c, "pkg:") && plainASCII(c) {
			// Canonicalization is idempotent for printable output without residual escapes.
			t.Fatalf("not idempotent: %q -> %q -> %q", s, c, CanonicalPURL(c))
		}
		_ = VulnFingerprint("CVE-1", s)
	})
}

// plainASCII reports whether s is printable ASCII without spaces or percent escapes.
func plainASCII(s string) bool {
	for i := range len(s) {
		if s[i] <= ' ' || s[i] > '~' || s[i] == '%' {
			return false
		}
	}
	return true
}
