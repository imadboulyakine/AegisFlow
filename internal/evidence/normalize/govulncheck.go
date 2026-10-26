package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

type govulnMessage struct {
	Config *struct {
		ProtocolVersion string `json:"protocol_version"`
		ScannerName     string `json:"scanner_name"`
		ScannerVersion  string `json:"scanner_version"`
		ScanLevel       string `json:"scan_level"`
		ScanMode        string `json:"scan_mode"`
	} `json:"config"`
	SBOM *struct {
		Modules []struct {
			Path    string `json:"path"`
			Version string `json:"version"`
		} `json:"modules"`
		Roots []string `json:"roots"`
	} `json:"SBOM"`
	OSV     *govulnOSV     `json:"osv"`
	Finding *govulnFinding `json:"finding"`
}

type govulnOSV struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	Published        string   `json:"published"`
	DatabaseSpecific *struct {
		CWEIDs []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

type govulnFinding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
	Trace        []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Package  string `json:"package"`
		Function string `json:"function"`
	} `json:"trace"`
}

// govulnGroup aggregates the findings of one (OSV, module) pair.
type govulnGroup struct {
	osv, module, version string
	level                int // 0 module, 1 package, 2 symbol (function)
	fixed                []string
}

// parseGovulncheck normalizes govulncheck's JSON message stream (protocol v1).
//
//   - config → Document.Tool (scanner_name/scanner_version), FormatVersion (protocol_version);
//   - SBOM → Subject (first root module) and Components (pkg:golang/<module>@<version>);
//   - one vulnerability Finding per (OSV ID, module): Component pkg:golang/<module>@<version>,
//     Vulnerability from the OSV entry (canonical CVE ID, GO-/GHSA- IDs as aliases; the Go
//     vulnerability database carries no CVSS, so severity is unknown), FixedVersions from
//     fixed_version;
//   - Reachability: called when any trace's first frame names a function; otherwise imported
//     when the scan ran at symbol level (the vulnerable package, or for module-level-only
//     findings the vulnerable module, is present but no vulnerable symbol is reachable);
//     otherwise (package- or module-level scans) unknown.
func parseGovulncheck(data []byte, b *builder) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var (
		configSeen bool
		scanLevel  string
		scanMode   string
		osvs       = map[string]*govulnOSV{}
		groups     []*govulnGroup
		groupIdx   = map[[2]string]int{}
	)
	for n := 0; ; n++ {
		var msg govulnMessage
		err := dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return invalidf("message %d: %v", n, err)
		}
		switch {
		case msg.Config != nil:
			if configSeen {
				return invalidf("message %d: duplicate config message", n)
			}
			configSeen = true
			c := msg.Config
			if !strings.HasPrefix(c.ProtocolVersion, "v1.") {
				return unsupportedVersion("protocol_version", c.ProtocolVersion)
			}
			b.doc.FormatVersion = c.ProtocolVersion
			b.doc.Tool = evidence.Tool{Name: firstNonEmpty(c.ScannerName, "govulncheck"), Version: c.ScannerVersion}
			scanLevel, scanMode = c.ScanLevel, c.ScanMode
			switch scanMode {
			case "", "source", "binary", "extract", "query":
			default:
				return invalidf("message %d: unknown scan_mode %q", n, clip(scanMode, 64))
			}
		case msg.SBOM != nil:
			roots := map[string]bool{}
			for _, r := range msg.SBOM.Roots {
				roots[r] = true
				if b.doc.Subject == nil {
					b.doc.Subject = &evidence.Artifact{Kind: evidence.ArtifactSource, Name: r}
				}
			}
			for _, m := range msg.SBOM.Modules {
				if m.Path == "" || roots[m.Path] {
					continue
				}
				if err := b.addComponent(newComponent(golangPURL(m.Path, m.Version), m.Path, m.Version, nil)); err != nil {
					return err
				}
			}
		case msg.OSV != nil:
			if msg.OSV.ID == "" {
				return invalidf("message %d: osv entry without id", n)
			}
			if _, dup := osvs[msg.OSV.ID]; !dup {
				osvs[msg.OSV.ID] = msg.OSV
			}
		case msg.Finding != nil:
			f := msg.Finding
			if f.OSV == "" || len(f.Trace) == 0 || f.Trace[0].Module == "" {
				return invalidf("message %d: finding without osv id or trace", n)
			}
			frame := f.Trace[0]
			level := 0
			switch {
			case frame.Function != "":
				level = 2
			case frame.Package != "":
				level = 1
			}
			key := [2]string{f.OSV, frame.Module}
			i, ok := groupIdx[key]
			if !ok {
				if len(groups) >= b.maxItems {
					return fmt.Errorf("%w: more than %d findings", ErrLimitExceeded, b.maxItems)
				}
				i = len(groups)
				groupIdx[key] = i
				groups = append(groups, &govulnGroup{osv: f.OSV, module: frame.Module, version: frame.Version})
			}
			g := groups[i]
			g.level = max(g.level, level)
			g.version = firstNonEmpty(g.version, frame.Version)
			g.fixed = appendUnique(g.fixed, f.FixedVersion)
		}
	}
	if !configSeen {
		return invalidf("missing config message")
	}
	if scanMode == "binary" && b.doc.Subject != nil {
		b.doc.Subject.Kind = evidence.ArtifactBinary
	}
	for _, g := range groups {
		if err := b.addFinding(govulnFindingFor(g, osvs[g.osv], scanLevel, b.doc.Tool)); err != nil {
			return err
		}
	}
	return nil
}

func govulnFindingFor(g *govulnGroup, osv *govulnOSV, scanLevel string, tool evidence.Tool) evidence.Finding {
	vuln := evidence.Vulnerability{ID: g.osv, Severity: evidence.SeverityUnknown}
	if osv != nil {
		vuln.ID, vuln.Aliases = canonicalVulnID(osv.ID, osv.Aliases)
		vuln.Summary = clip(firstNonEmpty(strings.TrimSpace(osv.Summary), firstLine(osv.Details)), maxMessageLen)
		if t, ok := parseTime(osv.Published); ok {
			vuln.Published = t
		}
		if osv.DatabaseSpecific != nil {
			vuln.CWEs = appendUnique(nil, osv.DatabaseSpecific.CWEIDs...)
		}
	}
	reach := evidence.ReachabilityUnknown
	switch {
	case g.level == 2:
		reach = evidence.ReachabilityCalled
	case scanLevel == "" || scanLevel == "symbol":
		reach = evidence.ReachabilityImported
	}
	comp := newComponent(golangPURL(g.module, g.version), g.module, g.version, nil)
	return evidence.Finding{
		Kind:          evidence.FindingVulnerability,
		Fingerprint:   VulnFingerprint(vuln.ID, comp.PURL),
		Title:         vulnTitle(vuln.ID, &comp),
		Message:       vuln.Summary,
		Severity:      vuln.Severity,
		RuleID:        g.osv,
		Tools:         toolList(tool),
		Vulnerability: &vuln,
		Component:     &comp,
		FixedVersions: g.fixed,
		Reachability:  reach,
	}
}

// golangPURL builds "pkg:golang/<module>@<version>" (module path kept literal, as syft and
// Grype emit it).
func golangPURL(module, version string) string {
	p := "pkg:golang/" + module
	if version != "" {
		p += "@" + version
	}
	return p
}
