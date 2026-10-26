package normalize

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

const minimalSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}`

func TestParseErrors(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("[", 70) + strings.Repeat("]", 70)
	tests := []struct {
		name   string
		format evidence.Format
		input  string
		opts   Options
		want   error
	}{
		{"too large", evidence.FormatSARIF, minimalSARIF, Options{MaxBytes: 10}, ErrTooLarge},
		{"unknown format value", evidence.Format("pdf"), minimalSARIF, Options{}, ErrUnknownFormat},
		{"undetectable", "", `{"hello":"world"}`, Options{}, ErrUnknownFormat},
		{"empty input", evidence.FormatSARIF, "", Options{}, ErrInvalid},
		{"whitespace only", evidence.FormatSARIF, " \n\t ", Options{}, ErrInvalid},
		{"malformed", evidence.FormatSARIF, `{"version":`, Options{}, ErrInvalid},
		{"trailing data", evidence.FormatSARIF, minimalSARIF + `{}`, Options{}, ErrInvalid},
		{"trailing garbage", evidence.FormatSARIF, minimalSARIF + `x`, Options{}, ErrInvalid},
		{"too deep", evidence.FormatSARIF, `{"runs":` + deep + `}`, Options{}, ErrLimitExceeded},
		{"custom depth", evidence.FormatSARIF, minimalSARIF, Options{MaxDepth: 3}, ErrLimitExceeded},
		{"duplicate key", evidence.FormatSARIF, `{"version":"2.1.0","version":"2.1.0","runs":[]}`, Options{}, ErrInvalid},
		{"case-folded duplicate key", evidence.FormatSARIF, `{"version":"2.1.0","VERSION":"9","runs":[]}`, Options{}, ErrInvalid},
		{"kelvin-sign duplicate key", evidence.FormatOpenVEX, `{"@context":"https://openvex.dev/ns/v0.2.0","kind":1,"Kind":2}`, Options{}, ErrInvalid},
		{"nested duplicate key", evidence.FormatSARIF, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"a","name":"b"}}}]}`, Options{}, ErrInvalid},
		{"not an object", evidence.FormatSARIF, `[]`, Options{}, ErrInvalid},
		{"wrong format for content", evidence.FormatSPDX, minimalSARIF, Options{}, ErrUnsupportedVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tt.format, strings.NewReader(tt.input), tt.opts)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseNilAndFailingReader(t *testing.T) {
	t.Parallel()
	if _, err := Parse(evidence.FormatSARIF, nil, Options{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil reader: %v", err)
	}
	readErr := errors.New("boom")
	if _, err := Parse(evidence.FormatSARIF, iotest.ErrReader(readErr), Options{}); !errors.Is(err, readErr) {
		t.Fatalf("failing reader: %v", err)
	}
}

func TestParseAutoDetectAndBOM(t *testing.T) {
	t.Parallel()
	input := append([]byte{0xEF, 0xBB, 0xBF}, minimalSARIF...)
	doc, err := Parse("", bytes.NewReader(input), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Format != evidence.FormatSARIF || doc.Tool.Name != "semgrep" || doc.FormatVersion != "2.1.0" {
		t.Fatalf("unexpected document: %+v", doc)
	}
}

func TestParseExactlyMaxBytes(t *testing.T) {
	t.Parallel()
	_, err := Parse(evidence.FormatSARIF, strings.NewReader(minimalSARIF), Options{MaxBytes: int64(len(minimalSARIF))})
	if err != nil {
		t.Fatalf("input of exactly MaxBytes must be accepted: %v", err)
	}
}

func TestMaxItems(t *testing.T) {
	t.Parallel()
	results := make([]string, 0, 3)
	for i := range 3 {
		results = append(results, fmt.Sprintf(`{"ruleId":"r%d","message":{"text":"m"}}`, i))
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[` + strings.Join(results, ",") + `]}]}`
	if _, err := ParseBytes("", []byte(sarif), Options{MaxItems: 3}); err != nil {
		t.Fatalf("3 findings with MaxItems 3: %v", err)
	}
	if _, err := ParseBytes("", []byte(sarif), Options{MaxItems: 2}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("3 findings with MaxItems 2: %v", err)
	}

	comps := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` +
		`{"name":"a","purl":"pkg:npm/a@1"},{"name":"b","purl":"pkg:npm/b@1"},{"name":"a2","purl":"pkg:npm/a@1"}]}`
	doc, err := ParseBytes("", []byte(comps), Options{MaxItems: 2})
	if err != nil || len(doc.Components) != 2 {
		t.Fatalf("duplicate purls must merge before the limit: %v %+v", err, doc)
	}
	if _, err := ParseBytes("", []byte(comps), Options{MaxItems: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("components over limit: %v", err)
	}

	vex := `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[` +
		`{"vulnerability":{"name":"CVE-2020-0001"},"products":[{"@id":"pkg:npm/a@1"}],"status":"affected"},` +
		`{"vulnerability":{"name":"CVE-2020-0002"},"products":[{"@id":"pkg:npm/a@1"}],"status":"affected"}]}`
	if _, err := ParseBytes("", []byte(vex), Options{MaxItems: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("VEX over limit: %v", err)
	}

	gv := `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}` +
		`{"finding":{"osv":"GO-1","trace":[{"module":"m1","version":"v1"}]}}` +
		`{"finding":{"osv":"GO-2","trace":[{"module":"m1","version":"v1"}]}}`
	if _, err := ParseBytes("", []byte(gv), Options{MaxItems: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("govulncheck groups over limit: %v", err)
	}
}

// TestOutputBudget checks that shared input text (one long rule description referenced by many
// results) cannot expand into an output much larger than the input.
func TestOutputBudget(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 200) // clipped to maxTitleLen per finding, still shared
	var results []string
	for i := range 20000 {
		results = append(results, fmt.Sprintf(`{"ruleIndex":0,"message":{"text":"%s"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"f%d"}}}]}`, strings.Repeat("y", 100), i))
	}
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[{"id":"r","shortDescription":{"text":"` +
		long + `"}}]}},"results":[` + strings.Join(results, ",") + `]}]}`
	if _, err := ParseBytes("", []byte(sarif), Options{}); err != nil {
		t.Fatalf("realistic expansion must fit the budget: %v", err)
	}

	b := newBuilder(evidence.FormatSARIF, 0, Options{}.withDefaults())
	b.budget = 100
	f := evidence.Finding{Title: strings.Repeat("t", 200)}
	if err := b.addFinding(f); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("budget exhaustion: %v", err)
	}
	b.budget = 10
	if err := b.addVEX(evidence.VEXStatement{VulnID: "CVE-1", Products: []string{"p"}}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("VEX budget exhaustion: %v", err)
	}
	b.budget = 10
	if err := b.addComponent(evidence.Component{PURL: "pkg:npm/a@1", Name: "a"}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("component budget exhaustion: %v", err)
	}
}

func TestOptionsDefaults(t *testing.T) {
	t.Parallel()
	o := Options{MaxBytes: -1, MaxItems: -1, MaxDepth: -1}.withDefaults()
	if o.MaxBytes != DefaultMaxBytes || o.MaxItems != DefaultMaxItems || o.MaxDepth != DefaultMaxDepth {
		t.Fatalf("defaults not applied: %+v", o)
	}
	o = Options{MaxBytes: 5, MaxItems: 6, MaxDepth: 7}.withDefaults()
	if o.MaxBytes != 5 || o.MaxItems != 6 || o.MaxDepth != 7 {
		t.Fatalf("explicit values overridden: %+v", o)
	}
}

func TestCheckJSONStream(t *testing.T) {
	t.Parallel()
	if err := checkJSON([]byte(`{"a":1} {"b":[1,2,{"c":null}]}`), 8, true); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if err := checkJSON([]byte(`{"a":1} {"a":2}`), 8, true); err != nil {
		t.Fatalf("same key in different stream values is fine: %v", err)
	}
	if err := checkJSON([]byte(`{"a":{"a":1}}`), 8, false); err != nil {
		t.Fatalf("same key at different levels is fine: %v", err)
	}
	if err := checkJSON([]byte(`[{"a":1},{"a":2}]`), 8, false); err != nil {
		t.Fatalf("same key in sibling objects is fine: %v", err)
	}
	if err := checkJSON([]byte(`{"a":[{"x":1}],"A":2}`), 8, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("case-folded duplicate after a nested value: %v", err)
	}
}

func TestFoldKey(t *testing.T) {
	t.Parallel()
	same := [][2]string{
		{"version", "VERSION"},
		{"kind", "Kind"},         // KELVIN SIGN folds to k
		{"ſhort", "SHORT"},       // LATIN SMALL LETTER LONG S folds to s
		{"Ünïcode", "üNÏCODE"},   // non-ASCII letters
		{"bom-ref", "BOM-REF"},   // punctuation preserved
		{"\xff\xfe", "\xff\xfe"}, // invalid UTF-8 is stable
		{"@context", "@CONTEXT"}, // symbols unchanged
		{"security-severity", "Security-Severity"},
	}
	for _, p := range same {
		if foldKey(p[0]) != foldKey(p[1]) {
			t.Errorf("foldKey(%q) != foldKey(%q)", p[0], p[1])
		}
	}
	if foldKey("version") == foldKey("versions") {
		t.Error("distinct keys folded together")
	}
}
