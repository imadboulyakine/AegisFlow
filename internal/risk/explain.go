package risk

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/intel"
)

// explanation carries the interpreted inputs behind a Result.
type explanation struct {
	cv       cvssChoice
	ep       epssChoice
	intel    intel.Intel
	reach    evidence.Reachability
	exposure Exposure
	vex      *evidence.VEXStatement
	raised   bool // the KEV override raised the tier
}

// reason renders the one-line explanation, e.g.
// "P1: CVSS 9.8, EPSS 0.94 (97th pct), in CISA KEV since 2026-03-02, reachable (called), internet-facing".
func reason(res Result, e explanation) string {
	vex := e.vex
	var b strings.Builder
	b.WriteString(string(res.Tier))
	if e.raised {
		b.WriteString(" (KEV override)")
	}
	b.WriteString(": ")
	if res.HasFlag(FlagVEXSuppressed) && vex != nil {
		b.WriteString("suppressed by VEX " + string(vex.Status))
		if j := strings.TrimSpace(vex.Justification); j != "" {
			b.WriteString(" (" + clean(j, 64) + ")")
		}
		b.WriteString("; ")
	}
	parts := []string{cvssPhrase(e.cv), epssPhrase(e.ep), kevPhrase(e.intel), reachPhrase(e.reach), exposurePhrase(e.exposure)}
	switch {
	case res.HasFlag(FlagVEXConflict):
		parts = append(parts, "VEX contradicts call-graph evidence")
	case res.HasFlag(FlagVEXIgnored):
		parts = append(parts, "VEX statement ignored")
	case vex != nil && !res.HasFlag(FlagVEXSuppressed):
		parts = append(parts, "VEX "+clean(string(vex.Status), 32))
	}
	b.WriteString(strings.Join(parts, ", "))
	return b.String()
}

func cvssPhrase(c cvssChoice) string {
	if c.estimated {
		return fmt.Sprintf("CVSS ~%.1f (estimated from %s severity)", c.score, severityName(c.severity))
	}
	return fmt.Sprintf("CVSS %.1f", c.score)
}

func epssPhrase(c epssChoice) string {
	if !c.known {
		return "EPSS unknown"
	}
	s := "EPSS " + formatProb(c.value)
	if c.pctKnown {
		s += " (" + ordinal(int(math.Floor(c.pct*100+1e-9))) + " pct)"
	}
	return s
}

func kevPhrase(in intel.Intel) string {
	switch {
	case in.KEV:
		s := "in CISA KEV"
		if !in.KEVDateAdded.IsZero() {
			s += " since " + in.KEVDateAdded.UTC().Format("2006-01-02")
		}
		if in.KEVRansomware {
			s += " (ransomware use)"
		}
		return s
	case !in.KEVChecked:
		return "KEV not checked"
	default:
		return "not in CISA KEV"
	}
}

func reachPhrase(r evidence.Reachability) string {
	switch r {
	case evidence.ReachabilityCalled:
		return "reachable (called)"
	case evidence.ReachabilityImported:
		return "not called (imported only)"
	default:
		return "reachability unknown"
	}
}

func exposurePhrase(x Exposure) string {
	switch x {
	case ExposureInternet:
		return "internet-facing"
	case ExposureInternal:
		return "internal"
	case ExposureBuild:
		return "build/dev-only"
	default:
		return "exposure unknown"
	}
}

// formatProb prints a probability compactly: 2 decimals from 0.01, 2 significant digits below.
func formatProb(v float64) string {
	switch {
	case v == 0:
		return "0"
	case v >= 0.01:
		return strconv.FormatFloat(v, 'f', 2, 64)
	default:
		return strconv.FormatFloat(v, 'g', 2, 64)
	}
}

// ordinal renders 1 → "1st", 2 → "2nd", 11 → "11th", 97 → "97th".
func ordinal(n int) string {
	n = max(0, min(100, n))
	suffix := "th"
	if n%100 < 11 || n%100 > 13 {
		switch n % 10 {
		case 1:
			suffix = "st"
		case 2:
			suffix = "nd"
		case 3:
			suffix = "rd"
		}
	}
	return strconv.Itoa(n) + suffix
}
