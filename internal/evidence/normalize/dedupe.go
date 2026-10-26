package normalize

import (
	"slices"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// Dedupe merges findings that share a fingerprint, keeping the position of the first occurrence.
// Findings without a fingerprint are kept as they are. Merging unions the tools (in order of
// appearance), fixed versions and vulnerability aliases/CVSS/CWEs, keeps the highest severity
// and the most informative reachability (called > imported > unknown > unset), and fills empty
// fields from later duplicates. The input slice and its findings are not modified.
//
// Parse applies Dedupe to every document; it is exported so that the ingest pipeline can merge
// findings across documents (for example Grype and govulncheck results for the same artifact).
func Dedupe(in []evidence.Finding) []evidence.Finding {
	if in == nil {
		return nil
	}
	out := make([]evidence.Finding, 0, len(in))
	idx := make(map[string]int, len(in))
	for i := range in {
		f := &in[i]
		if f.Fingerprint == "" {
			out = append(out, cloneFinding(f))
			continue
		}
		if j, ok := idx[f.Fingerprint]; ok {
			mergeInto(&out[j], f)
			continue
		}
		idx[f.Fingerprint] = len(out)
		out = append(out, cloneFinding(f))
	}
	return out
}

// cloneFinding deep-copies the slices and pointers of f so merges never alias the input.
func cloneFinding(f *evidence.Finding) evidence.Finding {
	c := *f
	c.Tools = slices.Clone(f.Tools)
	c.FixedVersions = slices.Clone(f.FixedVersions)
	if f.Vulnerability != nil {
		v := *f.Vulnerability
		v.Aliases = slices.Clone(v.Aliases)
		v.CVSS = slices.Clone(v.CVSS)
		v.CWEs = slices.Clone(v.CWEs)
		c.Vulnerability = &v
	}
	if f.Component != nil {
		comp := *f.Component
		comp.Licenses = slices.Clone(comp.Licenses)
		c.Component = &comp
	}
	if f.Location != nil {
		l := *f.Location
		c.Location = &l
	}
	return c
}

// mergeInto merges src into dst (dst is owned by Dedupe's output).
func mergeInto(dst *evidence.Finding, src *evidence.Finding) {
	for _, t := range src.Tools {
		if !slices.Contains(dst.Tools, t) {
			dst.Tools = append(dst.Tools, t)
		}
	}
	if src.Severity.Rank() > dst.Severity.Rank() {
		dst.Severity = src.Severity
	}
	if reachabilityRank(src.Reachability) > reachabilityRank(dst.Reachability) {
		dst.Reachability = src.Reachability
	}
	dst.FixedVersions = appendUnique(dst.FixedVersions, src.FixedVersions...)
	dst.Title = firstNonEmpty(dst.Title, src.Title)
	dst.Message = firstNonEmpty(dst.Message, src.Message)
	dst.RuleID = firstNonEmpty(dst.RuleID, src.RuleID)
	if dst.Kind == "" {
		dst.Kind = src.Kind
	}
	if dst.Component == nil && src.Component != nil {
		c := cloneFinding(&evidence.Finding{Component: src.Component})
		dst.Component = c.Component
	}
	if dst.Location == nil && src.Location != nil {
		l := *src.Location
		dst.Location = &l
	}
	if src.Vulnerability != nil {
		if dst.Vulnerability == nil {
			c := cloneFinding(&evidence.Finding{Vulnerability: src.Vulnerability})
			dst.Vulnerability = c.Vulnerability
		} else {
			mergeVulnerability(dst.Vulnerability, src.Vulnerability)
		}
	}
}

func mergeVulnerability(dst, src *evidence.Vulnerability) {
	if src.ID != dst.ID {
		dst.Aliases = appendUnique(dst.Aliases, src.ID)
	}
	for _, a := range src.Aliases {
		if a != dst.ID {
			dst.Aliases = appendUnique(dst.Aliases, a)
		}
	}
	for _, c := range src.CVSS {
		if !slices.Contains(dst.CVSS, c) {
			dst.CVSS = append(dst.CVSS, c)
		}
	}
	dst.CWEs = appendUnique(dst.CWEs, src.CWEs...)
	dst.Summary = firstNonEmpty(dst.Summary, src.Summary)
	if src.Severity.Rank() > dst.Severity.Rank() {
		dst.Severity = src.Severity
	}
	if dst.Published.IsZero() {
		dst.Published = src.Published
	}
}

// reachabilityRank orders reachability by information content: a tool that knows the
// vulnerable code is called (or only imported) beats one that cannot tell.
func reachabilityRank(r evidence.Reachability) int {
	switch r {
	case evidence.ReachabilityCalled:
		return 3
	case evidence.ReachabilityImported:
		return 2
	case evidence.ReachabilityUnknown:
		return 1
	default:
		return 0
	}
}
