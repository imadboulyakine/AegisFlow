package risk

import (
	"fmt"
	"slices"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/intel"
)

// Exposure is the deployment context of the artifact a finding affects.
type Exposure string

// Exposure levels (ARCHITECTURE.md §7: internet 1.0, internal 0.6, build 0.3).
const (
	ExposureUnknown  Exposure = "unknown"
	ExposureInternet Exposure = "internet" // internet-facing production
	ExposureInternal Exposure = "internal" // reachable only from a private network
	ExposureBuild    Exposure = "build"    // build, CI or dev-only dependency
)

// ParseExposure parses an exposure name (case-insensitive); "" means ExposureUnknown.
func ParseExposure(s string) (Exposure, error) {
	switch e := Exposure(strings.ToLower(strings.TrimSpace(s))); e {
	case "":
		return ExposureUnknown, nil
	case ExposureUnknown, ExposureInternet, ExposureInternal, ExposureBuild:
		return e, nil
	default:
		return "", fmt.Errorf("unknown exposure %q (want internet, internal, build or unknown)", s)
	}
}

// IntelSource looks up vulnerability intelligence; intel.Snapshot and intel.MemoryStore
// implement it.
type IntelSource interface {
	LookupAll(cves []string) intel.Intel
}

// Input is everything the engine needs to score one finding. Build it with NewInput or set
// the fields directly (e.g. from a stored, frozen experiment dataset).
type Input struct {
	// FindingID identifies the finding in results (normally evidence.Finding.Fingerprint).
	FindingID string `json:"findingId,omitempty"`
	// VulnID and Aliases identify the vulnerability; a VEX statement must name one of them.
	VulnID       string                `json:"vulnId,omitempty"`
	Aliases      []string              `json:"aliases,omitempty"`
	CVSS         []evidence.CVSS       `json:"cvss,omitempty"`
	Severity     evidence.Severity     `json:"severity,omitempty"`
	Intel        intel.Intel           `json:"intel"`
	Reachability evidence.Reachability `json:"reachability,omitempty"`
	Exposure     Exposure              `json:"exposure,omitempty"`
	// VEX is the statement that applies to this finding's product, if any. Matching a
	// statement's products to the finding is the caller's job; the engine only checks that the
	// statement names this vulnerability and is well-formed.
	VEX *evidence.VEXStatement `json:"vex,omitempty"`
}

// NewInput builds an Input from a normalized finding. src may be nil (no intelligence); when
// set, the intelligence of all the vulnerability's CVE aliases is merged (intel.LookupAll).
// The finding's severity is used, falling back to the vulnerability's when unknown.
func NewInput(f evidence.Finding, src IntelSource, exposure Exposure, vex *evidence.VEXStatement) Input {
	in := Input{
		FindingID:    f.Fingerprint,
		Severity:     f.Severity,
		Reachability: f.Reachability,
		Exposure:     exposure,
		VEX:          vex,
	}
	if v := f.Vulnerability; v != nil {
		in.VulnID = v.ID
		in.Aliases = slices.Clone(v.Aliases)
		in.CVSS = slices.Clone(v.CVSS)
		if in.Severity.Rank() == 0 {
			in.Severity = v.Severity
		}
		if src != nil {
			in.Intel = src.LookupAll(v.CVEs())
		}
	}
	return in
}

// matchesVuln reports whether id names this input's vulnerability (ID or alias).
func (in Input) matchesVuln(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	for _, own := range append([]string{in.VulnID}, in.Aliases...) {
		if own != "" && strings.EqualFold(strings.TrimSpace(own), id) {
			return true
		}
	}
	return false
}
