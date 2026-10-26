package normalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// cdxSupportedVersions are the CycloneDX JSON specification versions accepted.
var cdxSupportedVersions = map[string]bool{"1.4": true, "1.5": true, "1.6": true, "1.7": true}

type cdxBOM struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Metadata        *cdxMetadata       `json:"metadata"`
	Components      []cdxComponent     `json:"components"`
	Dependencies    []cdxDependency    `json:"dependencies"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxMetadata struct {
	// Tools is an array of tools (1.4, legacy in 1.5+) or {components, services} (1.5+).
	Tools     json.RawMessage `json:"tools"`
	Component *cdxComponent   `json:"component"`
}

type cdxTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxToolChoice struct {
	Components []cdxTool `json:"components"`
	Services   []cdxTool `json:"services"`
}

type cdxComponent struct {
	BOMRef     string             `json:"bom-ref"`
	Type       string             `json:"type"`
	Group      string             `json:"group"`
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	PURL       string             `json:"purl"`
	Licenses   []cdxLicenseChoice `json:"licenses"`
	Hashes     []cdxHash          `json:"hashes"`
	Properties []cdxProperty      `json:"properties"`
	Components []cdxComponent     `json:"components"`
}

type cdxLicenseChoice struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxVulnerability struct {
	ID         string `json:"id"`
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Ratings []struct {
		Score    *float64 `json:"score"`
		Severity string   `json:"severity"`
		Method   string   `json:"method"`
		Vector   string   `json:"vector"`
	} `json:"ratings"`
	CWEs        []int  `json:"cwes"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	Published   string `json:"published"`
	Updated     string `json:"updated"`
	Affects     []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
	Analysis *struct {
		State         string `json:"state"`
		Justification string `json:"justification"`
		Detail        string `json:"detail"`
		LastUpdated   string `json:"lastUpdated"`
	} `json:"analysis"`
}

// cdxRatingMethods maps CycloneDX rating methods to CVSS versions.
var cdxRatingMethods = map[string]string{
	"cvssv2": "2.0", "cvssv3": "3.0", "cvssv31": "3.1", "cvssv4": "4.0",
}

// cdxAnalysisStates maps CycloneDX impact-analysis states to VEX statuses.
var cdxAnalysisStates = map[string]evidence.VEXStatus{
	"not_affected":           evidence.VEXNotAffected,
	"false_positive":         evidence.VEXNotAffected,
	"exploitable":            evidence.VEXAffected,
	"resolved":               evidence.VEXFixed,
	"resolved_with_pedigree": evidence.VEXFixed,
	"in_triage":              evidence.VEXUnderInvestigation,
}

// parseCycloneDX normalizes a CycloneDX JSON BOM (1.4–1.7).
//
//   - metadata.tools (either shape) → Document.Tool (first named tool);
//   - metadata.component → Subject (digest from a pkg:oci PURL, a *RepoDigest/*manifestDigest
//     property, or a SHA-256/384/512 hash);
//   - components (flattened, nested included) with a valid PURL → Components; components
//     without a PURL (files, operating systems) are skipped;
//   - dependencies → Component.Direct for refs the root depends on (see dependencyGraph.direct);
//   - vulnerabilities → one vulnerability Finding per affected component, unless the analysis
//     state says it is not exploitable (not_affected, false_positive, resolved*), and one
//     VEXStatement per vulnerability carrying an analysis state.
func parseCycloneDX(data []byte, b *builder) error {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return invalidf("decode: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return invalidf("bomFormat must be \"CycloneDX\"")
	}
	if !cdxSupportedVersions[bom.SpecVersion] {
		return unsupportedVersion("specVersion", bom.SpecVersion)
	}
	doc := b.doc
	doc.FormatVersion = bom.SpecVersion

	var root *cdxComponent
	if bom.Metadata != nil {
		tool, err := cdxDocumentTool(bom.Metadata.Tools)
		if err != nil {
			return err
		}
		doc.Tool = tool
		root = bom.Metadata.Component
	}
	if root != nil {
		doc.Subject = cdxSubject(root)
	}

	// Flatten components (iteratively; depth is already bounded by checkJSON).
	var flat []*cdxComponent
	stack := make([]*cdxComponent, 0, len(bom.Components))
	for i := len(bom.Components) - 1; i >= 0; i-- {
		stack = append(stack, &bom.Components[i])
	}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		flat = append(flat, c)
		for i := len(c.Components) - 1; i >= 0; i-- {
			stack = append(stack, &c.Components[i])
		}
	}

	byRef := make(map[string]*cdxComponent, len(flat)+1)
	if root != nil && root.BOMRef != "" {
		byRef[root.BOMRef] = root
	}
	for i, c := range flat {
		if c.Name == "" {
			return invalidf("component %d: missing name", i)
		}
		if c.BOMRef != "" {
			byRef[c.BOMRef] = c
		}
	}

	graph := newDependencyGraph()
	for _, d := range bom.Dependencies {
		for _, to := range d.DependsOn {
			graph.addEdge(d.Ref, to)
		}
	}
	rootRef := ""
	if root != nil {
		rootRef = root.BOMRef
	}
	direct := graph.direct(rootRef, func(ref string) bool {
		c, ok := byRef[ref]
		return ok && (c == root || unversioned(c.Version))
	})

	for _, c := range flat {
		if !validPURL(c.PURL) {
			continue
		}
		comp := newComponent(c.PURL, cdxName(c), c.Version, cdxLicenses(c.Licenses))
		comp.Direct = direct[c.BOMRef]
		if err := b.addComponent(comp); err != nil {
			return err
		}
	}

	for i := range bom.Vulnerabilities {
		if err := cdxVulnerabilityItems(&bom.Vulnerabilities[i], i, byRef, b); err != nil {
			return err
		}
	}
	return nil
}

// cdxDocumentTool decodes metadata.tools in either the 1.4 array shape or the 1.5+ object shape.
func cdxDocumentTool(raw json.RawMessage) (evidence.Tool, error) {
	raw = bytes.TrimSpace(raw)
	var tools []cdxTool
	switch {
	case len(raw) == 0 || bytes.Equal(raw, []byte("null")):
		return evidence.Tool{}, nil
	case raw[0] == '[':
		if err := json.Unmarshal(raw, &tools); err != nil {
			return evidence.Tool{}, invalidf("metadata.tools: %v", err)
		}
	case raw[0] == '{':
		var choice cdxToolChoice
		if err := json.Unmarshal(raw, &choice); err != nil {
			return evidence.Tool{}, invalidf("metadata.tools: %v", err)
		}
		tools = slices.Concat(choice.Components, choice.Services)
	default:
		return evidence.Tool{}, invalidf("metadata.tools must be an array or an object")
	}
	for _, t := range tools {
		if t.Name != "" {
			return evidence.Tool{Name: t.Name, Version: t.Version}, nil
		}
	}
	return evidence.Tool{}, nil
}

func cdxName(c *cdxComponent) string {
	if c.Group != "" {
		return c.Group + "/" + c.Name
	}
	return c.Name
}

func cdxLicenses(choices []cdxLicenseChoice) []string {
	var out []string
	for _, l := range choices {
		switch {
		case l.Expression != "":
			out = appendUnique(out, strings.TrimSpace(l.Expression))
		case l.License != nil:
			out = appendUnique(out, strings.TrimSpace(firstNonEmpty(l.License.ID, l.License.Name)))
		}
	}
	return out
}

// cdxSubject builds the document subject from metadata.component.
func cdxSubject(c *cdxComponent) *evidence.Artifact {
	if c.Name == "" {
		return nil
	}
	dig, ok := digestFromOCIPURL(c.PURL)
	if !ok {
		for _, p := range c.Properties {
			name := strings.ToLower(p.Name)
			if strings.HasSuffix(name, "repodigest") || strings.HasSuffix(name, "manifestdigest") {
				if dig, ok = digestFromReference(p.Value); ok {
					break
				}
			}
		}
	}
	if !ok {
		for _, h := range c.Hashes {
			if dig, ok = digestFromChecksum(h.Alg, h.Content); ok {
				break
			}
		}
	}
	return newArtifact(artifactKind(c.Type, ok), cdxName(c), dig)
}

// cdxVulnerabilityItems turns one CycloneDX vulnerability into findings and a VEX statement.
func cdxVulnerabilityItems(v *cdxVulnerability, idx int, byRef map[string]*cdxComponent, b *builder) error {
	if strings.TrimSpace(v.ID) == "" {
		return invalidf("vulnerability %d: missing id", idx)
	}
	aliases := make([]string, 0, len(v.References))
	for _, r := range v.References {
		aliases = append(aliases, r.ID)
	}
	id, rest := canonicalVulnID(v.ID, aliases)
	vuln := evidence.Vulnerability{
		ID:       id,
		Aliases:  rest,
		Summary:  clip(firstNonEmpty(strings.TrimSpace(v.Description), firstLine(v.Detail)), maxMessageLen),
		Severity: evidence.SeverityUnknown,
	}
	for _, r := range v.Ratings {
		vuln.Severity = maxSeverity(vuln.Severity, evidence.ParseSeverity(r.Severity))
		ver, isCVSS := cdxRatingMethods[strings.ToLower(r.Method)]
		if isCVSS && r.Score != nil {
			if c, ok := newCVSS(ver, r.Vector, *r.Score); ok {
				vuln.CVSS = appendCVSS(vuln.CVSS, c)
			}
		}
	}
	if vuln.Severity == evidence.SeverityUnknown {
		vuln.Severity = severityFromCVSS(vuln.CVSS)
	}
	for _, cwe := range v.CWEs {
		if cwe > 0 {
			vuln.CWEs = appendUnique(vuln.CWEs, "CWE-"+strconv.Itoa(cwe))
		}
	}
	if t, ok := parseTime(v.Published); ok {
		vuln.Published = t
	}

	var status evidence.VEXStatus
	if v.Analysis != nil && v.Analysis.State != "" {
		s, known := cdxAnalysisStates[v.Analysis.State]
		if !known {
			return invalidf("vulnerability %d: unknown analysis state %q", idx, clip(v.Analysis.State, 64))
		}
		status = s
	}

	var products []string
	for _, a := range v.Affects {
		ref := strings.TrimSpace(a.Ref)
		if ref == "" {
			continue
		}
		var comp *evidence.Component
		if c, ok := byRef[ref]; ok {
			cc := newComponent(c.PURL, cdxName(c), c.Version, cdxLicenses(c.Licenses))
			comp = &cc
		} else if validPURL(ref) {
			cc := newComponent(ref, purlName(ref), purlVersion(ref), nil)
			comp = &cc
		}
		if comp != nil {
			products = appendUnique(products, comp.PURL)
		} else {
			products = appendUnique(products, ref)
		}
		if comp == nil || status == evidence.VEXNotAffected || status == evidence.VEXFixed {
			continue
		}
		vc := vuln
		f := evidence.Finding{
			Kind:          evidence.FindingVulnerability,
			Fingerprint:   VulnFingerprint(vuln.ID, comp.PURL),
			Title:         vulnTitle(vuln.ID, comp),
			Message:       vuln.Summary,
			Severity:      vuln.Severity,
			RuleID:        strings.TrimSpace(v.ID),
			Tools:         toolList(b.doc.Tool),
			Vulnerability: &vc,
			Component:     comp,
			Reachability:  evidence.ReachabilityUnknown,
		}
		if err := b.addFinding(f); err != nil {
			return err
		}
	}

	if status == "" {
		return nil
	}
	if len(products) == 0 {
		return invalidf("vulnerability %d: analysis without affected components", idx)
	}
	stmt := evidence.VEXStatement{
		VulnID:          vuln.ID,
		Products:        products,
		Status:          status,
		Justification:   v.Analysis.Justification,
		ImpactStatement: clip(strings.TrimSpace(v.Analysis.Detail), maxMessageLen),
	}
	if stmt.Justification == "" && v.Analysis.State == "false_positive" {
		stmt.Justification = "false_positive"
	}
	for _, ts := range []string{v.Analysis.LastUpdated, v.Updated, v.Published} {
		if t, ok := parseTime(ts); ok {
			stmt.Timestamp = t
			break
		}
	}
	if err := b.addVEX(stmt); err != nil {
		return fmt.Errorf("vulnerability %d: %w", idx, err)
	}
	return nil
}

// toolList returns []Tool{t}, or nil when t has no name.
func toolList(t evidence.Tool) []evidence.Tool {
	if t.Name == "" {
		return nil
	}
	return []evidence.Tool{t}
}

// purlName returns the percent-decoded namespace/name of a package URL.
func purlName(purl string) string {
	_, name, _, _ := splitPURL(purl)
	return name
}

// purlVersion returns the percent-decoded version of a package URL.
func purlVersion(purl string) string {
	_, _, version, _ := splitPURL(purl)
	return version
}
