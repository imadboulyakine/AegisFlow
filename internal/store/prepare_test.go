package store

import (
	"encoding/base64"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func vulnFinding(fp, vulnID, purl string, tool string) evidence.Finding {
	return evidence.Finding{
		Kind: evidence.FindingVulnerability, Fingerprint: fp, Title: "vuln " + vulnID, Severity: evidence.SeverityHigh,
		Tools:         []evidence.Tool{{Name: tool, Version: "1.0"}},
		Vulnerability: &evidence.Vulnerability{ID: vulnID, Severity: evidence.SeverityHigh},
		Component:     &evidence.Component{PURL: purl, Name: "pkg", Version: "1.0.0"},
	}
}

func TestPrepareDocumentRejects(t *testing.T) {
	t.Parallel()
	base := func() evidence.Document {
		return evidence.Document{Format: evidence.FormatGrype, Tool: evidence.Tool{Name: "grype"}}
	}
	tests := []struct {
		name   string
		mutate func(*evidence.Document)
		want   string
	}{
		{"unknown format", func(d *evidence.Document) { d.Format = "trivy" }, "unknown format"},
		{"missing tool", func(d *evidence.Document) { d.Tool.Name = "  " }, "tool name"},
		{"too many components", func(d *evidence.Document) { d.Components = make([]evidence.Component, maxDocComponents+1) }, "components exceed"},
		{"too many findings", func(d *evidence.Document) { d.Findings = make([]evidence.Finding, maxDocFindings+1) }, "findings exceed"},
		{"too many vex", func(d *evidence.Document) { d.VEX = make([]evidence.VEXStatement, maxDocVEX+1) }, "VEX statements exceed"},
		{"empty fingerprint", func(d *evidence.Document) {
			d.Findings = []evidence.Finding{{Kind: evidence.FindingCode}}
		}, "fingerprint"},
		{"unknown kind", func(d *evidence.Document) {
			d.Findings = []evidence.Finding{{Kind: "malware", Fingerprint: "x"}}
		}, "unknown kind"},
		{"vulnerability finding without vulnerability", func(d *evidence.Document) {
			d.Findings = []evidence.Finding{{Kind: evidence.FindingVulnerability, Fingerprint: "x"}}
		}, "without a vulnerability"},
		{"bad vulnerability id", func(d *evidence.Document) {
			d.Findings = []evidence.Finding{vulnFinding("x", "CVE 2024 1", "pkg:golang/a@1", "grype")}
		}, "invalid vulnerability ID"},
		{"bad reachability", func(d *evidence.Document) {
			f := vulnFinding("x", "CVE-2024-0001", "pkg:golang/a@1", "grype")
			f.Reachability = "maybe"
			d.Findings = []evidence.Finding{f}
		}, "unknown reachability"},
		{"vex bad vuln", func(d *evidence.Document) {
			d.VEX = []evidence.VEXStatement{{VulnID: "", Status: evidence.VEXAffected, Products: []string{"p"}}}
		}, "invalid vulnerability ID"},
		{"vex bad status", func(d *evidence.Document) {
			d.VEX = []evidence.VEXStatement{{VulnID: "CVE-2024-0001", Status: "maybe", Products: []string{"p"}}}
		}, "unknown status"},
		{"vex bad justification", func(d *evidence.Document) {
			d.VEX = []evidence.VEXStatement{{VulnID: "CVE-2024-0001", Status: evidence.VEXNotAffected, Justification: "trust me", Products: []string{"p"}}}
		}, "unknown justification"},
		{"vex no products", func(d *evidence.Document) {
			d.VEX = []evidence.VEXStatement{{VulnID: "CVE-2024-0001", Status: evidence.VEXAffected}}
		}, "no products"},
		{"vex empty product", func(d *evidence.Document) {
			d.VEX = []evidence.VEXStatement{{VulnID: "CVE-2024-0001", Status: evidence.VEXAffected, Products: []string{" "}}}
		}, "product must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := base()
			tt.mutate(&d)
			_, err := prepareDocument(d)
			if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("prepareDocument() error = %v, want ErrInvalidInput containing %q", err, tt.want)
			}
		})
	}
}

func TestPrepareDocumentMergesAndSorts(t *testing.T) {
	t.Parallel()
	published := time.Date(2024, 5, 1, 10, 0, 0, 123456789, time.FixedZone("x", 3600))
	f1 := vulnFinding("fp-b", "CVE-2024-0002", "pkg:golang/b@1", "Grype")
	f1.Vulnerability.Aliases = []string{"GHSA-aaaa-bbbb-cccc", "CVE-2024-0002", "bad alias!", "GHSA-aaaa-bbbb-cccc"}
	f1.Vulnerability.CVSS = []evidence.CVSS{
		{Version: "3.1", Vector: "AV:N", BaseScore: 7.5},
		{Version: "3.1", Vector: "AV:N", BaseScore: 7.5}, // duplicate
		{Version: "3.1", BaseScore: math.NaN()},          // dropped
		{Version: "", BaseScore: 5},                      // dropped
	}
	f1.Vulnerability.Published = published
	f1.FixedVersions = []string{"1.2.0", "1.1.9"}
	f2 := vulnFinding("fp-b", "CVE-2024-0002", "pkg:golang/b@1", "trivy") // duplicate fingerprint
	f2.Severity = evidence.SeverityCritical
	f2.Reachability = evidence.ReachabilityCalled
	f2.Title = ""
	f2.FixedVersions = []string{"1.2.0", "2.0.0"}
	f2.Vulnerability.Severity = evidence.SeverityCritical
	f2.Vulnerability.Published = published.Add(-time.Hour)
	f2.Vulnerability.CVSS = []evidence.CVSS{{Version: "4.0", BaseScore: 9.1}}
	f3 := evidence.Finding{
		Kind: evidence.FindingCode, Fingerprint: "fp-a", Title: "  sql\x00injection  ", Severity: "error",
		Location: &evidence.Location{Path: "main.go", StartLine: 10, EndLine: -1},
	}
	doc := evidence.Document{
		Format: evidence.FormatGrype, Tool: evidence.Tool{Name: " GRYPE "},
		Components: []evidence.Component{
			{PURL: "pkg:golang/z@1", Name: "z", Licenses: []string{"MIT", "Apache-2.0", "MIT", ""}},
			{PURL: "pkg:golang/z@1", Version: "1", Licenses: []string{"BSD-3-Clause"}, Direct: true}, // merged
			{PURL: "not-a-purl", Name: "skipped"},
			{PURL: "", Name: "also skipped"},
		},
		Findings: []evidence.Finding{f1, f3, f2},
		VEX: []evidence.VEXStatement{
			{VulnID: "CVE-2024-0002", Status: evidence.VEXNotAffected, Justification: "component_not_present",
				Products: []string{"pkg:golang/b@1", "sha256:abc"}, Timestamp: published},
			{VulnID: "CVE-2024-0002", Status: evidence.VEXNotAffected, Justification: "component_not_present",
				Products: []string{"pkg:golang/b@1"}, Timestamp: published}, // duplicate pair
		},
	}
	p, err := prepareDocument(doc)
	if err != nil {
		t.Fatalf("prepareDocument() error = %v", err)
	}

	if want := []string{"grype", "trivy"}; !slices.Equal(p.tools, want) {
		t.Errorf("tools = %v, want %v", p.tools, want)
	}
	if p.skippedComponents != 2 {
		t.Errorf("skippedComponents = %d, want 2", p.skippedComponents)
	}
	if len(p.components) != 2 || p.components[0].PURL != "pkg:golang/b@1" || p.components[1].PURL != "pkg:golang/z@1" {
		t.Fatalf("components = %+v", p.components)
	}
	z := p.components[1]
	if z.Name != "z" || z.Version != "1" || !z.Direct || z.Ecosystem != "golang" ||
		!slices.Equal(z.Licenses, []string{"Apache-2.0", "BSD-3-Clause", "MIT"}) {
		t.Errorf("merged component = %+v", z)
	}

	if len(p.vulns) != 1 {
		t.Fatalf("vulns = %+v", p.vulns)
	}
	v := p.vulns[0]
	if v.Severity != "critical" || !slices.Equal(v.Aliases, []string{"GHSA-aaaa-bbbb-cccc"}) || len(v.CVSS) != 2 {
		t.Errorf("merged vuln = %+v", v)
	}
	if v.Published == nil || !v.Published.Equal(published.Add(-time.Hour).Truncate(time.Microsecond)) || v.Published.Location() != time.UTC {
		t.Errorf("published = %v", v.Published)
	}

	if len(p.findings) != 2 || p.findings[0].Fingerprint != "fp-a" || p.findings[1].Fingerprint != "fp-b" {
		t.Fatalf("findings = %+v", p.findings)
	}
	code := p.findings[0]
	if code.Title != "sql�injection" || code.Severity != "high" || !slices.Equal(code.Tools, []string{"grype"}) ||
		code.LocationPath == nil || *code.LocationPath != "main.go" || code.LocationStart == nil || *code.LocationStart != 10 ||
		code.LocationEnd != nil || code.Reachability != nil {
		t.Errorf("code finding = %+v", code)
	}
	vf := p.findings[1]
	if vf.Severity != "critical" || vf.Title != "vuln CVE-2024-0002" || vf.Reachability == nil || *vf.Reachability != "called" ||
		!slices.Equal(vf.Tools, []string{"grype", "trivy"}) || !slices.Equal(vf.FixedVersions, []string{"1.1.9", "1.2.0", "2.0.0"}) ||
		vf.purl != "pkg:golang/b@1" || vf.vulnID != "CVE-2024-0002" {
		t.Errorf("merged vulnerability finding = %+v", vf)
	}

	if len(p.vex) != 2 {
		t.Fatalf("vex rows = %+v", p.vex)
	}
	for _, r := range p.vex {
		if len(r.DedupKey) != 64 || r.StatementTime == nil {
			t.Errorf("vex row = %+v", r)
		}
	}
	if p.vex[0].DedupKey > p.vex[1].DedupKey {
		t.Error("vex rows must be sorted by dedup key")
	}
}

func TestPrepareDocumentIsDeterministic(t *testing.T) {
	t.Parallel()
	doc := evidence.Document{Format: evidence.FormatGrype, Tool: evidence.Tool{Name: "grype"}}
	for i := range 50 {
		purl := "pkg:npm/p" + strconv.Itoa(i%26) + "@1"
		doc.Findings = append(doc.Findings, vulnFinding("fp"+purl, "CVE-2024-"+strconv.Itoa(1000+i%26), purl, "grype"))
	}
	a, err := prepareDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(doc.Findings)
	b, err := prepareDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.findings) != len(b.findings) {
		t.Fatal("different lengths")
	}
	for i := range a.findings {
		if a.findings[i].Fingerprint != b.findings[i].Fingerprint {
			t.Fatalf("order depends on input order at %d", i)
		}
	}
}

func TestComponentCap(t *testing.T) {
	t.Parallel()
	// Finding packages count towards the component limit too.
	doc := evidence.Document{Format: evidence.FormatGrype, Tool: evidence.Tool{Name: "grype"}}
	doc.Components = make([]evidence.Component, maxDocComponents)
	for i := range doc.Components {
		doc.Components[i] = evidence.Component{PURL: "pkg:generic/c" + strconv.Itoa(i) + "@1"}
	}
	doc.Findings = []evidence.Finding{vulnFinding("fp", "CVE-2024-0001", "pkg:generic/extra@1", "grype")}
	p, err := prepareDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.components) != maxDocComponents || p.skippedComponents != 1 || p.findings[0].purl != "" {
		t.Errorf("components = %d, skipped = %d, finding purl = %q", len(p.components), p.skippedComponents, p.findings[0].purl)
	}
}

func encodeRaw(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestTextHelpers(t *testing.T) {
	t.Parallel()
	if got := cleanText("  héllo\x00\xffworld  ", 100); got != "héllo��world" {
		t.Errorf("cleanText = %q", got)
	}
	if got := cleanText("ééé", 3); got != "é" { // 2-byte runes: never cut inside one
		t.Errorf("cleanText truncation = %q", got)
	}
	if got := cleanText("abc", 0); got != "" {
		t.Errorf("cleanText(max 0) = %q", got)
	}
	if got := cleanList([]string{"b", " a ", "b", "", "c"}, 10, 2); !slices.Equal(got, []string{"b", "a"}) {
		t.Errorf("cleanList = %v", got)
	}
	for _, tc := range []struct {
		s      string
		ok     bool
		minLen int
	}{{"ok", true, 1}, {"", false, 1}, {"", true, 0}, {"a\x00", false, 0}, {"\xff", false, 0}, {strings.Repeat("a", 11), false, 0}} {
		if got := boundedText(tc.s, tc.minLen, 10); got != tc.ok {
			t.Errorf("boundedText(%q) = %v", tc.s, got)
		}
	}
	for _, tc := range []struct {
		in string
		ok bool
	}{{`{}`, true}, {` {"a":1}`, true}, {`[]`, false}, {`{`, false}, {`"x"`, false}, {``, false}} {
		if got := isJSONObject([]byte(tc.in)); got != tc.ok {
			t.Errorf("isJSONObject(%q) = %v", tc.in, got)
		}
	}
	if got := lineNumber(math.MaxInt32 + 1); got != nil {
		t.Errorf("lineNumber overflow = %v", *got)
	}
	if got := mergeLists(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("mergeLists(nil, nil) = %#v, want empty non-nil", got)
	}
}

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		score float64
		id    int64
	}{{-1, 1}, {0, 42}, {72.35, 9_000_000_000}, {100, 7}, {33.333333333333336, 3}} {
		s, id, err := decodeCursor(encodeCursor(tc.score, tc.id))
		if err != nil || s != tc.score || id != tc.id {
			t.Errorf("round trip (%v, %d) = (%v, %d, %v)", tc.score, tc.id, s, id, err)
		}
	}
	enc := encodeRaw
	for _, bad := range []string{
		"!!!", strings.Repeat("A", 200), enc("v2|1|1"), enc("v1|1"), enc("v1|NaN|1"), enc("v1|101|1"),
		enc("v1|-2|1"), enc("v1|1|0"), enc("v1|1|x"), enc("v1|x|1"),
	} {
		if _, _, err := decodeCursor(bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("decodeCursor(%q) error = %v, want ErrInvalidInput", bad, err)
		}
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	if classify(nil) != nil {
		t.Error("classify(nil) != nil")
	}
	plain := errors.New("boom")
	if !errors.Is(classify(plain), plain) || errors.Is(classify(plain), ErrConflict) {
		t.Error("non-PostgreSQL errors must pass through unchanged")
	}
	already := invalid("x")
	if got := classify(already); got.Error() != already.Error() || !errors.Is(got, ErrInvalidInput) {
		t.Error("classified errors must not be wrapped twice")
	}
	if retryable(plain) {
		t.Error("plain errors are not retryable")
	}
}
