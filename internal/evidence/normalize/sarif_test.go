package normalize

import (
	"errors"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestSARIFFixtures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file     string
		tool     string
		kind     evidence.FindingKind
		findings int
	}{
		{"sarif-gitleaks.json", "gitleaks", evidence.FindingSecret, 2},
		{"sarif-gosec.json", "gosec", evidence.FindingCode, 5},
		{"sarif-zizmor.json", "zizmor", evidence.FindingConfig, 4},
		{"sarif-trivy-config.json", "Trivy", evidence.FindingConfig, 4},
	}
	for _, tt := range tests {
		doc := parseFixture(t, tt.file)
		if doc.Tool.Name != tt.tool || len(doc.Findings) != tt.findings {
			t.Errorf("%s: tool %q, %d findings", tt.file, doc.Tool.Name, len(doc.Findings))
		}
		for _, f := range doc.Findings {
			if f.Kind != tt.kind || f.Location == nil || f.Location.Path == "" || f.Location.StartLine == 0 {
				t.Errorf("%s: finding %+v", tt.file, f)
			}
		}
	}
	// gitleaks sets no level: secrets default to high, and the redacted snippet never leaks.
	for _, f := range parseFixture(t, "sarif-gitleaks.json").Findings {
		if f.Severity != evidence.SeverityHigh || strings.Contains(f.Message, "REDACTED") {
			t.Errorf("gitleaks finding = %+v", f)
		}
	}
	// gosec: upper-case severity tags win over the blanket "error" level.
	sev := map[string]evidence.Severity{}
	for _, f := range parseFixture(t, "sarif-gosec.json").Findings {
		sev[f.RuleID] = f.Severity
	}
	if sev["G401"] != evidence.SeverityMedium || sev["G702"] != evidence.SeverityHigh {
		t.Errorf("gosec severities = %v", sev)
	}
	// trivy: security-severity 5.5 → medium; tag "misconfiguration" → config.
	if f := parseFixture(t, "sarif-trivy-config.json").Findings[0]; f.Severity != evidence.SeverityMedium || f.Title != "':latest' tag used" {
		t.Errorf("trivy finding = %+v", f)
	}
}

func sarifDoc(driver, results string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":` + driver + `},"results":[` + results + `]}]}`
}

func TestSARIFEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("skipped results", func(t *testing.T) {
		t.Parallel()
		doc := mustParse(t, evidence.FormatSARIF, sarifDoc(`{"name":"semgrep"}`, `
			{"ruleId":"a","kind":"pass","message":{"text":"m"}},
			{"ruleId":"b","kind":"notApplicable","message":{"text":"m"}},
			{"ruleId":"c","baselineState":"absent","message":{"text":"m"}},
			{"ruleId":"d","suppressions":[{"kind":"inSource"}],"message":{"text":"m"}},
			{"ruleId":"e","suppressions":[{"kind":"external","status":"accepted"}],"message":{"text":"m"}},
			{"ruleId":"f","suppressions":[{"kind":"external","status":"underReview"}],"kind":"review","message":{"text":"kept"}}`))
		if len(doc.Findings) != 1 || doc.Findings[0].RuleID != "f" || doc.Findings[0].Message != "kept" {
			t.Fatalf("findings = %+v", doc.Findings)
		}
	})

	t.Run("rule resolution, severity and kind", func(t *testing.T) {
		t.Parallel()
		driver := `{"name":"CodeQL","semanticVersion":"2.20.0","rules":[
			{"id":"go/a","shortDescription":{"text":"Rule A\nmore"},"properties":{"security-severity":"9.8"}},
			{"id":"go/b","fullDescription":{"text":"Rule B full"},"defaultConfiguration":{"level":"note"},"properties":{"security-severity":"n/a"}},
			{"id":"CA2000","name":"DisposeObjects"}]}`
		doc := mustParse(t, evidence.FormatSARIF, `{"version":"2.1.0","runs":[{"tool":{"driver":`+driver+`,
			"extensions":[{"name":"pack","rules":[{"id":"ext/x","shortDescription":{"text":"Ext rule"},"properties":{"security-severity":6.1}}]}]},
			"results":[
			  {"ruleIndex":0,"message":{"text":"a"}},
			  {"rule":{"id":"go/b","index":1},"message":{"markdown":"b md"}},
			  {"rule":{"id":"ext/x","index":0,"toolComponent":{"index":0}},"message":{"text":"x"}},
			  {"rule":{"id":"ext/y","index":0,"toolComponent":{"index":7}},"message":{"text":"y"}},
			  {"ruleId":"CA2000/sub","ruleIndex":99,"level":"none","message":{"text":"c"},"properties":{"security-severity":0}},
			  {"ruleId":"unknown","level":"error","message":{"text":"first\nsecond"},
			   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/src/a%20b.go"},"region":{"startLine":-4}}}]},
			  {"message":{"text":"no rule"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"https://example.com/x.go"}}}]},
			  {"message":{"text":""},"locations":[{},{"physicalLocation":{"artifactLocation":{"uri":".\\dir\\file.go"},"region":{"startLine":3,"endLine":4,"snippet":{"text":"x"}}}}]}
			]}]}`)
		type want struct {
			title string
			sev   evidence.Severity
			path  string
		}
		wants := []want{
			{"Rule A", evidence.SeverityCritical, ""},
			{"Rule B full", evidence.SeverityInfo, ""},
			{"Ext rule", evidence.SeverityMedium, ""},
			{"ext/y", evidence.SeverityMedium, ""},
			{"DisposeObjects", evidence.SeverityInfo, ""},
			{"unknown", evidence.SeverityHigh, "/repo/src/a b.go"},
			{"no rule", evidence.SeverityMedium, "https://example.com/x.go"},
			{"CodeQL finding", evidence.SeverityMedium, "dir/file.go"},
		}
		if len(doc.Findings) != len(wants) {
			t.Fatalf("findings = %d, want %d", len(doc.Findings), len(wants))
		}
		for i, w := range wants {
			f := doc.Findings[i]
			if f.Kind != evidence.FindingCode || f.Title != w.title || f.Severity != w.sev {
				t.Errorf("finding %d = %q %s %s, want %q %s", i, f.Title, f.Kind, f.Severity, w.title, w.sev)
			}
			path := ""
			if f.Location != nil {
				path = f.Location.Path
			}
			if path != w.path {
				t.Errorf("finding %d path = %q, want %q", i, path, w.path)
			}
		}
		if doc.Findings[1].Message != "b md" || doc.Tool.Version != "2.20.0" {
			t.Errorf("markdown message / semanticVersion fallback: %+v %+v", doc.Findings[1], doc.Tool)
		}
		if l := doc.Findings[5].Location; l.StartLine != 0 {
			t.Errorf("negative line must clamp to 0: %+v", l)
		}
		if l := doc.Findings[7].Location; l.StartLine != 3 || l.EndLine != 4 {
			t.Errorf("region = %+v", l)
		}
	})

	t.Run("kind by tool and tags", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			driver string
			props  string
			want   evidence.FindingKind
		}{
			{`{"name":"TruffleHog"}`, `{}`, evidence.FindingSecret},
			{`{"name":"OWASP ZAP"}`, `{}`, evidence.FindingDAST},
			{`{"name":"checkov"}`, `{}`, evidence.FindingConfig},
			{`{"name":"Trivy"}`, `{"tags":["secret"]}`, evidence.FindingSecret},
			{`{"name":"Trivy"}`, `{"tags":["IaC"]}`, evidence.FindingConfig},
			{`{"name":"Trivy"}`, `{"tags":["vulnerability"]}`, evidence.FindingCode},
			{`{"name":"some-linter"}`, `{}`, evidence.FindingCode},
		}
		for _, c := range cases {
			doc := mustParse(t, evidence.FormatSARIF, sarifDoc(c.driver, `{"ruleId":"r","message":{"text":"m"},"properties":`+c.props+`}`))
			if doc.Findings[0].Kind != c.want {
				t.Errorf("%s %s: kind %s, want %s", c.driver, c.props, doc.Findings[0].Kind, c.want)
			}
		}
	})

	t.Run("multiple runs and null runs", func(t *testing.T) {
		t.Parallel()
		doc := mustParse(t, evidence.FormatSARIF, `{"version":"2.1.0","runs":[
			{"tool":{"driver":{"name":"a","version":"1"}},"results":[{"ruleId":"r","message":{"text":"m"}}]},
			{"tool":{"driver":{"name":"b"}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`)
		if doc.Tool.Name != "a" || len(doc.Findings) != 2 || doc.Findings[1].Tools[0].Name != "b" {
			t.Errorf("multi-run = %+v", doc)
		}
		doc = mustParse(t, evidence.FormatSARIF, `{"version":"2.1.0","runs":null}`)
		if len(doc.Findings) != 0 {
			t.Errorf("null runs = %+v", doc)
		}
	})

	t.Run("duplicate results merge", func(t *testing.T) {
		t.Parallel()
		r := `{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}`
		doc := mustParse(t, evidence.FormatSARIF, sarifDoc(`{"name":"semgrep"}`, r+","+r))
		if len(doc.Findings) != 1 {
			t.Errorf("findings = %d, want 1", len(doc.Findings))
		}
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name, input string
			want        error
		}{
			{"version 2.0", `{"version":"2.0.0","runs":[]}`, ErrUnsupportedVersion},
			{"missing driver name", sarifDoc(`{"name":" "}`, ``), ErrInvalid},
			{"tags not strings", sarifDoc(`{"name":"x","rules":[{"id":"r","properties":{"tags":[1]}}]}`, ``), ErrInvalid},
			{"results not array", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":{}}]}`, ErrInvalid},
		}
		for _, c := range cases {
			if _, err := parseString(t, evidence.FormatSARIF, c.input); !errors.Is(err, c.want) {
				t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
			}
		}
	})
}
