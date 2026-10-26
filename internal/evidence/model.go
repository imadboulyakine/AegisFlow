// Package evidence is AegisFlow's tool-agnostic domain model for software supply-chain
// evidence: artifacts, components, vulnerabilities, findings and VEX statements.
//
// Normalizers (internal/evidence/normalize) convert tool output (CycloneDX, SPDX, SARIF, Grype,
// govulncheck, OpenVEX) into these types; the risk engine, policy engine and store consume them.
// The types are plain data: no I/O, no behaviour beyond small helpers, JSON-serialisable.
package evidence

import (
	"strings"
	"time"
)

// Format identifies the evidence document format a Document was normalized from.
type Format string

// Supported evidence formats.
const (
	FormatCycloneDX   Format = "cyclonedx"
	FormatSPDX        Format = "spdx"
	FormatSARIF       Format = "sarif"
	FormatGrype       Format = "grype"
	FormatGovulncheck Format = "govulncheck"
	FormatOpenVEX     Format = "openvex"
)

// Tool identifies the scanner or generator that produced a piece of evidence.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ArtifactKind classifies what an Artifact is.
type ArtifactKind string

// Artifact kinds.
const (
	ArtifactContainerImage ArtifactKind = "container-image"
	ArtifactBinary         ArtifactKind = "binary"
	ArtifactSource         ArtifactKind = "source"
	ArtifactSBOM           ArtifactKind = "sbom"
)

// Artifact is a build output, always identified by content digest, never by tag.
type Artifact struct {
	Kind ArtifactKind `json:"kind"`
	// Name is a human-readable reference (image repository, file name, repo path).
	Name string `json:"name"`
	// Digest is "<algorithm>:<hex>", normally "sha256:<64 hex>". Empty when unknown.
	Digest string `json:"digest,omitempty"`
}

// Component is a software package found in an SBOM or scan.
type Component struct {
	// PURL is the package URL (https://github.com/package-url/purl-spec); the primary key.
	PURL    string `json:"purl"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// Ecosystem is the purl type: "golang", "npm", "deb", "apk", "generic", ...
	Ecosystem string   `json:"ecosystem,omitempty"`
	Licenses  []string `json:"licenses,omitempty"`
	// Direct is true for first-level dependencies when the source format says so.
	Direct bool `json:"direct,omitempty"`
}

// EcosystemFromPURL returns the purl type ("golang" for "pkg:golang/..."), or "" if invalid.
func EcosystemFromPURL(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	typ, _, ok := strings.Cut(rest, "/")
	if !ok {
		return ""
	}
	return strings.ToLower(typ)
}

// Severity is a normalized qualitative severity.
type Severity string

// Severities, ordered by Rank.
const (
	SeverityUnknown  Severity = "unknown"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank orders severities (unknown 0 … critical 5) for comparisons and thresholds.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// ParseSeverity maps common tool spellings ("HIGH", "Moderate", "negligible", "error", ...)
// to a Severity. Unrecognized values map to SeverityUnknown.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high", "error":
		return SeverityHigh
	case "medium", "moderate", "warning":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "negligible", "note", "none":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// CVSS is one CVSS rating of a vulnerability.
type CVSS struct {
	// Version is "2.0", "3.0", "3.1" or "4.0".
	Version   string  `json:"version"`
	Vector    string  `json:"vector,omitempty"`
	BaseScore float64 `json:"baseScore"`
}

// Vulnerability is an advisory, OSV-shaped.
type Vulnerability struct {
	// ID is the canonical identifier: the CVE when one exists, else the source ID (GHSA-…, GO-…).
	ID        string    `json:"id"`
	Aliases   []string  `json:"aliases,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	CVSS      []CVSS    `json:"cvss,omitempty"`
	Severity  Severity  `json:"severity"`
	CWEs      []string  `json:"cwes,omitempty"`
	Published time.Time `json:"published,omitzero"`
}

// CVEs returns every CVE identifier among ID and Aliases (deduplicated, original order).
func (v Vulnerability) CVEs() []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Reachability states whether vulnerable code is reachable from the scanned program.
type Reachability string

// Reachability levels (ARCHITECTURE.md §7: called 1.0, unknown 0.7, imported 0.3).
const (
	ReachabilityUnknown  Reachability = "unknown"
	ReachabilityCalled   Reachability = "called"   // a vulnerable symbol is in the call graph
	ReachabilityImported Reachability = "imported" // vulnerable package/module present but not called
)

// FindingKind classifies a Finding.
type FindingKind string

// Finding kinds.
const (
	FindingVulnerability FindingKind = "vulnerability" // SCA / image scan
	FindingCode          FindingKind = "code"          // SAST
	FindingSecret        FindingKind = "secret"        // secret scanning
	FindingConfig        FindingKind = "config"        // IaC / workflow misconfiguration
	FindingDAST          FindingKind = "dast"          // dynamic scan
)

// Location points into source code for code, secret and config findings.
type Location struct {
	Path      string `json:"path"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
}

// Finding is one normalized issue reported by one or more tools.
type Finding struct {
	Kind FindingKind `json:"kind"`
	// Fingerprint is a stable, tool-independent key used to deduplicate and track a finding
	// across runs (see Fingerprint helpers in the normalize package).
	Fingerprint string   `json:"fingerprint"`
	Title       string   `json:"title"`
	Message     string   `json:"message,omitempty"`
	Severity    Severity `json:"severity"`
	RuleID      string   `json:"ruleId,omitempty"`
	Tools       []Tool   `json:"tools"`

	// Vulnerability findings.
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`
	Component     *Component     `json:"component,omitempty"`
	FixedVersions []string       `json:"fixedVersions,omitempty"`
	Reachability  Reachability   `json:"reachability,omitempty"`

	// Code, secret and config findings.
	Location *Location `json:"location,omitempty"`
}

// VEXStatus is an OpenVEX status.
type VEXStatus string

// OpenVEX 0.2.0 statuses.
const (
	VEXNotAffected        VEXStatus = "not_affected"
	VEXAffected           VEXStatus = "affected"
	VEXFixed              VEXStatus = "fixed"
	VEXUnderInvestigation VEXStatus = "under_investigation"
)

// VEXStatement asserts the exploitability status of a vulnerability in products.
type VEXStatement struct {
	VulnID string `json:"vulnId"`
	// Products are PURLs or artifact digests.
	Products        []string  `json:"products"`
	Status          VEXStatus `json:"status"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impactStatement,omitempty"`
	Author          string    `json:"author,omitempty"`
	Timestamp       time.Time `json:"timestamp,omitzero"`
}

// Document is the normalized content of one evidence file.
type Document struct {
	Format        Format `json:"format"`
	FormatVersion string `json:"formatVersion,omitempty"`
	Tool          Tool   `json:"tool"`
	// Subject is what was scanned or described, when the document says so.
	Subject    *Artifact      `json:"subject,omitempty"`
	Components []Component    `json:"components,omitempty"`
	Findings   []Finding      `json:"findings,omitempty"`
	VEX        []VEXStatement `json:"vex,omitempty"`
}
