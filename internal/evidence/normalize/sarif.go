package normalize

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver     sarifToolComponent   `json:"driver"`
	Extensions []sarifToolComponent `json:"extensions"`
}

type sarifToolComponent struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name"`
	ShortDescription     *sarifMessage    `json:"shortDescription"`
	FullDescription      *sarifMessage    `json:"fullDescription"`
	DefaultConfiguration *sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifProperties  `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifProperties struct {
	SecuritySeverity flexFloat `json:"security-severity"`
	Tags             []string  `json:"tags"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Rule      *struct {
		ID            string `json:"id"`
		Index         *int   `json:"index"`
		ToolComponent *struct {
			Index *int `json:"index"`
		} `json:"toolComponent"`
	} `json:"rule"`
	Kind      string       `json:"kind"`
	Level     string       `json:"level"`
	Message   sarifMessage `json:"message"`
	Locations []struct {
		PhysicalLocation *struct {
			ArtifactLocation *struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
				Snippet   *struct {
					Text string `json:"text"`
				} `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	Suppressions []struct {
		Status string `json:"status"`
	} `json:"suppressions"`
	BaselineState string          `json:"baselineState"`
	Properties    sarifProperties `json:"properties"`
}

// sarifToolKinds classifies findings by scanner (lower-cased driver name contains the key).
// Evaluated in order; the first match wins.
var sarifToolKinds = []struct {
	key  string
	kind evidence.FindingKind
}{
	{"gitleaks", evidence.FindingSecret},
	{"trufflehog", evidence.FindingSecret},
	{"detect-secrets", evidence.FindingSecret},
	{"ggshield", evidence.FindingSecret},
	{"secretlint", evidence.FindingSecret},
	{"noseyparker", evidence.FindingSecret},
	{"zizmor", evidence.FindingConfig},
	{"actionlint", evidence.FindingConfig},
	{"poutine", evidence.FindingConfig},
	{"checkov", evidence.FindingConfig},
	{"tfsec", evidence.FindingConfig},
	{"kics", evidence.FindingConfig},
	{"terrascan", evidence.FindingConfig},
	{"hadolint", evidence.FindingConfig},
	{"kube-linter", evidence.FindingConfig},
	{"kubesec", evidence.FindingConfig},
	{"psrule", evidence.FindingConfig},
	{"template analyzer", evidence.FindingConfig},
	{"templateanalyzer", evidence.FindingConfig},
	{"bicep", evidence.FindingConfig},
	{"zap", evidence.FindingDAST},
	{"nuclei", evidence.FindingDAST},
	{"semgrep", evidence.FindingCode},
	{"gosec", evidence.FindingCode},
	{"codeql", evidence.FindingCode},
}

// parseSARIF normalizes a SARIF 2.1.0 log: every result of every run becomes a Finding.
//
//   - Kind comes from the scanner name (sarifToolKinds); for other scanners rule/result tags
//     "secret(s)" → secret and "misconfiguration"/"iac" → config; everything else is code.
//   - Severity: numeric "security-severity" (result, then rule properties) banded with
//     SeverityFromScore; else an upper-case severity tag (gosec/trivy convention); else the
//     result level, the rule default level, or SARIF's implicit "warning" — except that secret
//     findings without any severity information are high.
//   - Results that are not failures (kind pass/notApplicable), are suppressed (accepted or
//     unconditional suppressions) or are absent from the current run (baselineState "absent")
//     are skipped.
//   - The first physical location → Location; the fingerprint is LocationFingerprint over tool,
//     rule, path, start line and the region snippet (hashed, never stored).
func parseSARIF(data []byte, b *builder) error {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return invalidf("decode: %v", err)
	}
	if log.Version != "2.1.0" {
		return unsupportedVersion("version", log.Version)
	}
	b.doc.FormatVersion = log.Version
	for ri := range log.Runs {
		run := &log.Runs[ri]
		driver := &run.Tool.Driver
		if strings.TrimSpace(driver.Name) == "" {
			return invalidf("run %d: tool.driver.name is required", ri)
		}
		tool := evidence.Tool{Name: driver.Name, Version: firstNonEmpty(driver.Version, driver.SemanticVersion)}
		if ri == 0 {
			b.doc.Tool = tool
		}
		rulesByID := map[string]*sarifRule{}
		for _, comp := range append([]sarifToolComponent{*driver}, run.Tool.Extensions...) {
			for i := range comp.Rules {
				r := &comp.Rules[i]
				if _, seen := rulesByID[r.ID]; !seen && r.ID != "" {
					rulesByID[r.ID] = r
				}
			}
		}
		for i := range run.Results {
			f, keep := sarifFinding(&run.Results[i], run, rulesByID, tool)
			if !keep {
				continue
			}
			if err := b.addFinding(f); err != nil {
				return fmt.Errorf("run %d result %d: %w", ri, i, err)
			}
		}
	}
	return nil
}

func sarifFinding(res *sarifResult, run *sarifRun, rulesByID map[string]*sarifRule, tool evidence.Tool) (evidence.Finding, bool) {
	switch res.Kind {
	case "pass", "notApplicable":
		return evidence.Finding{}, false
	}
	if res.BaselineState == "absent" {
		return evidence.Finding{}, false
	}
	for _, s := range res.Suppressions {
		if s.Status == "" || s.Status == "accepted" {
			return evidence.Finding{}, false
		}
	}

	rule := sarifLookupRule(res, run, rulesByID)
	ruleID := res.RuleID
	if ruleID == "" && res.Rule != nil {
		ruleID = res.Rule.ID
	}
	if ruleID == "" && rule != nil {
		ruleID = rule.ID
	}

	kind := sarifKind(tool.Name, rule, res)
	f := evidence.Finding{
		Kind:     kind,
		Title:    clip(sarifTitle(rule, ruleID, res, tool.Name), maxTitleLen),
		Message:  clip(strings.TrimSpace(firstNonEmpty(res.Message.Text, res.Message.Markdown)), maxMessageLen),
		Severity: sarifSeverity(res, rule, kind),
		RuleID:   ruleID,
		Tools:    []evidence.Tool{tool},
	}

	snippet := ""
	for _, loc := range res.Locations {
		pl := loc.PhysicalLocation
		if pl == nil || pl.ArtifactLocation == nil || pl.ArtifactLocation.URI == "" {
			continue
		}
		l := &evidence.Location{Path: sarifPath(pl.ArtifactLocation.URI)}
		if pl.Region != nil {
			l.StartLine = max(pl.Region.StartLine, 0)
			l.EndLine = max(pl.Region.EndLine, 0)
			if pl.Region.Snippet != nil {
				snippet = pl.Region.Snippet.Text
			}
		}
		f.Location = l
		break
	}
	path, line := "", 0
	if f.Location != nil {
		path, line = f.Location.Path, f.Location.StartLine
	}
	f.Fingerprint = LocationFingerprint(tool.Name, ruleID, path, line, snippet)
	return f, true
}

// sarifLookupRule resolves the result's rule: an extension rule via rule.toolComponent.index,
// a driver rule via ruleIndex/rule.index, else any rule with the result's rule ID. All indexes
// are bounds-checked.
func sarifLookupRule(res *sarifResult, run *sarifRun, rulesByID map[string]*sarifRule) *sarifRule {
	rules := run.Tool.Driver.Rules
	idx := res.RuleIndex
	if res.Rule != nil {
		if res.Rule.Index != nil {
			idx = res.Rule.Index
		}
		if tc := res.Rule.ToolComponent; tc != nil && tc.Index != nil {
			if *tc.Index < 0 || *tc.Index >= len(run.Tool.Extensions) {
				rules = nil
			} else {
				rules = run.Tool.Extensions[*tc.Index].Rules
			}
		}
	}
	if idx != nil && *idx >= 0 && *idx < len(rules) {
		return &rules[*idx]
	}
	id := res.RuleID
	if id == "" && res.Rule != nil {
		id = res.Rule.ID
	}
	if r, ok := rulesByID[id]; ok {
		return r
	}
	// Hierarchical rule IDs ("CA2000/sub") fall back to their base rule.
	if base, _, ok := strings.Cut(id, "/"); ok {
		if r, ok := rulesByID[base]; ok {
			return r
		}
	}
	return nil
}

func sarifKind(toolName string, rule *sarifRule, res *sarifResult) evidence.FindingKind {
	name := strings.ToLower(toolName)
	for _, tk := range sarifToolKinds {
		if strings.Contains(name, tk.key) {
			return tk.kind
		}
	}
	tags := slices.Clone(res.Properties.Tags)
	if rule != nil {
		tags = append(tags, rule.Properties.Tags...)
	}
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "secret", "secrets":
			return evidence.FindingSecret
		case "misconfiguration", "iac":
			return evidence.FindingConfig
		}
	}
	return evidence.FindingCode
}

func sarifSeverity(res *sarifResult, rule *sarifRule, kind evidence.FindingKind) evidence.Severity {
	scores := []flexFloat{res.Properties.SecuritySeverity}
	if rule != nil {
		scores = append(scores, rule.Properties.SecuritySeverity)
	}
	for _, s := range scores {
		if s.Set {
			if sev := SeverityFromScore(s.Value); sev != evidence.SeverityUnknown {
				return sev
			}
		}
	}
	if rule != nil {
		for _, t := range rule.Properties.Tags {
			switch t {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW":
				return evidence.ParseSeverity(t)
			}
		}
	}
	level := res.Level
	if level == "" && rule != nil && rule.DefaultConfiguration != nil {
		level = rule.DefaultConfiguration.Level
	}
	if level == "" {
		if kind == evidence.FindingSecret {
			return evidence.SeverityHigh
		}
		level = "warning"
	}
	return evidence.ParseSeverity(level)
}

func sarifTitle(rule *sarifRule, ruleID string, res *sarifResult, toolName string) string {
	if rule != nil {
		if rule.ShortDescription != nil {
			if t := firstLine(rule.ShortDescription.Text); t != "" {
				return t
			}
		}
		if rule.FullDescription != nil {
			if t := firstLine(rule.FullDescription.Text); t != "" {
				return t
			}
		}
		if rule.Name != "" {
			return rule.Name
		}
	}
	if ruleID != "" {
		return ruleID
	}
	if t := firstLine(res.Message.Text); t != "" {
		return t
	}
	return toolName + " finding"
}

// sarifPath turns a SARIF artifact URI into a slash-separated path: file:// URIs become their
// path, relative references are percent-decoded, other absolute URIs are kept verbatim.
func sarifPath(uri string) string {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return cleanPath(uri)
	}
	switch strings.ToLower(u.Scheme) {
	case "", "file":
		return cleanPath(u.Path)
	default:
		return uri
	}
}
