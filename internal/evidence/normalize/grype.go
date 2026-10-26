package normalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

type grypeDocument struct {
	Matches *[]grypeMatch `json:"matches"`
	Source  *struct {
		Type   string          `json:"type"`
		Target json.RawMessage `json:"target"`
	} `json:"source"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability          grypeVulnerability `json:"vulnerability"`
	RelatedVulnerabilities []grypeVulnMeta    `json:"relatedVulnerabilities"`
	Artifact               struct {
		Name     string          `json:"name"`
		Version  string          `json:"version"`
		PURL     string          `json:"purl"`
		Licenses json.RawMessage `json:"licenses"`
	} `json:"artifact"`
}

type grypeVulnMeta struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	CVSS        []struct {
		Version string `json:"version"`
		Vector  string `json:"vector"`
		Metrics struct {
			BaseScore *float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
	CWEs []struct {
		CWE string `json:"cwe"`
	} `json:"cwes"`
}

type grypeVulnerability struct {
	grypeVulnMeta
	Fix struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
}

type grypeImageTarget struct {
	UserInput      string   `json:"userInput"`
	ManifestDigest string   `json:"manifestDigest"`
	RepoDigests    []string `json:"repoDigests"`
	Tags           []string `json:"tags"`
	Path           string   `json:"path"`
}

// parseGrype normalizes Grype's JSON output (`grype -o json`).
//
//   - descriptor → Document.Tool; source → Subject (image: digest from the user input, then
//     repoDigests, then manifestDigest; directory → source; file → binary);
//   - each match → a vulnerability Finding: Component from the artifact (PURL, synthesized
//     pkg:generic when missing), Vulnerability with the canonical CVE ID (from the match or its
//     relatedVulnerabilities) and the others as aliases, Grype's severity (or the CVSS band when
//     Grype says Unknown), CVSS from the match or, if it has none, from the related records,
//     fix.versions → FixedVersions. Reachability is unknown;
//   - ignoredMatches are skipped (Grype's own configuration excluded them).
func parseGrype(data []byte, b *builder) error {
	var doc grypeDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return invalidf("decode: %v", err)
	}
	if doc.Matches == nil {
		return invalidf("matches array is required")
	}
	if strings.TrimSpace(doc.Descriptor.Name) == "" {
		return invalidf("descriptor.name is required")
	}
	b.doc.Tool = evidence.Tool{Name: doc.Descriptor.Name, Version: doc.Descriptor.Version}
	if doc.Source != nil {
		subject, err := grypeSubject(doc.Source.Type, doc.Source.Target)
		if err != nil {
			return err
		}
		b.doc.Subject = subject
	}
	for i := range *doc.Matches {
		m := &(*doc.Matches)[i]
		f, err := grypeFinding(m, b.doc.Tool)
		if err != nil {
			return fmt.Errorf("match %d: %w", i, err)
		}
		if err := b.addFinding(f); err != nil {
			return fmt.Errorf("match %d: %w", i, err)
		}
	}
	return nil
}

func grypeFinding(m *grypeMatch, tool evidence.Tool) (evidence.Finding, error) {
	v := &m.Vulnerability
	if strings.TrimSpace(v.ID) == "" {
		return evidence.Finding{}, invalidf("vulnerability.id is required")
	}
	if strings.TrimSpace(m.Artifact.Name) == "" {
		return evidence.Finding{}, invalidf("artifact.name is required")
	}
	related := make([]string, 0, len(m.RelatedVulnerabilities))
	for _, r := range m.RelatedVulnerabilities {
		related = append(related, r.ID)
	}
	id, aliases := canonicalVulnID(v.ID, related)
	vuln := evidence.Vulnerability{
		ID:       id,
		Aliases:  aliases,
		Severity: evidence.ParseSeverity(v.Severity),
		CVSS:     grypeCVSS(&v.grypeVulnMeta),
	}
	summary := strings.TrimSpace(v.Description)
	for i := range m.RelatedVulnerabilities {
		r := &m.RelatedVulnerabilities[i]
		if len(vuln.CVSS) == 0 {
			vuln.CVSS = grypeCVSS(r)
		}
		summary = firstNonEmpty(summary, strings.TrimSpace(r.Description))
		for _, c := range r.CWEs {
			vuln.CWEs = appendUnique(vuln.CWEs, strings.TrimSpace(c.CWE))
		}
	}
	for _, c := range v.CWEs {
		vuln.CWEs = appendUnique(vuln.CWEs, strings.TrimSpace(c.CWE))
	}
	vuln.Summary = clip(summary, maxMessageLen)
	if vuln.Severity == evidence.SeverityUnknown {
		vuln.Severity = severityFromCVSS(vuln.CVSS)
	}
	comp := newComponent(m.Artifact.PURL, m.Artifact.Name, m.Artifact.Version, grypeLicenses(m.Artifact.Licenses))
	var fixed []string
	for _, fv := range v.Fix.Versions {
		fixed = appendUnique(fixed, strings.TrimSpace(fv))
	}
	return evidence.Finding{
		Kind:          evidence.FindingVulnerability,
		Fingerprint:   VulnFingerprint(vuln.ID, comp.PURL),
		Title:         vulnTitle(vuln.ID, &comp),
		Message:       vuln.Summary,
		Severity:      vuln.Severity,
		RuleID:        strings.TrimSpace(v.ID),
		Tools:         toolList(tool),
		Vulnerability: &vuln,
		Component:     &comp,
		FixedVersions: fixed,
		Reachability:  evidence.ReachabilityUnknown,
	}, nil
}

func grypeCVSS(m *grypeVulnMeta) []evidence.CVSS {
	var out []evidence.CVSS
	for _, c := range m.CVSS {
		if c.Metrics.BaseScore == nil {
			continue
		}
		if cv, ok := newCVSS(c.Version, c.Vector, *c.Metrics.BaseScore); ok {
			out = appendCVSS(out, cv)
		}
	}
	return out
}

// grypeLicenses accepts the shapes Grype has used for artifact.licenses: strings, or objects
// with "value"/"spdxExpression". Anything else is ignored (licenses are informational here).
func grypeLicenses(raw json.RawMessage) []string {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		var s string
		if json.Unmarshal(it, &s) == nil {
			out = appendUnique(out, strings.TrimSpace(s))
			continue
		}
		var obj struct {
			Value          string `json:"value"`
			SPDXExpression string `json:"spdxExpression"`
		}
		if json.Unmarshal(it, &obj) == nil {
			out = appendUnique(out, strings.TrimSpace(firstNonEmpty(obj.SPDXExpression, obj.Value)))
		}
	}
	return out
}

func grypeSubject(typ string, target json.RawMessage) (*evidence.Artifact, error) {
	target = bytes.TrimSpace(target)
	var name string
	var img grypeImageTarget
	switch {
	case len(target) == 0 || bytes.Equal(target, []byte("null")):
		return nil, nil
	case target[0] == '"':
		if err := json.Unmarshal(target, &name); err != nil {
			return nil, invalidf("source.target: %v", err)
		}
	case target[0] == '{':
		if err := json.Unmarshal(target, &img); err != nil {
			return nil, invalidf("source.target: %v", err)
		}
		name = firstNonEmpty(img.UserInput, img.Path)
	default:
		return nil, invalidf("source.target must be a string or an object")
	}
	switch strings.ToLower(typ) {
	case "image":
		ref := name
		if ref == "" && len(img.Tags) > 0 {
			ref = img.Tags[0]
		}
		a := newArtifact(evidence.ArtifactContainerImage, ref, "")
		candidates := append([]string{name}, img.RepoDigests...)
		candidates = append(candidates, img.ManifestDigest)
		for _, c := range candidates {
			if !strings.Contains(c, "sha256:") && !strings.Contains(c, "sha512:") {
				continue
			}
			if d, ok := digestFromReference(c); ok {
				a.Digest = d
				break
			}
		}
		return a, nil
	case "directory":
		return &evidence.Artifact{Kind: evidence.ArtifactSource, Name: name}, nil
	case "file":
		return &evidence.Artifact{Kind: evidence.ArtifactBinary, Name: name}, nil
	default:
		return nil, nil
	}
}
