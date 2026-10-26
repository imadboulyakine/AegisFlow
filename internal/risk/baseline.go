package risk

import (
	"errors"
	"fmt"
	"math"
	"slices"
)

// BaselineConfig parameterizes the CVSS-only baseline of Experiment E2.
type BaselineConfig struct {
	// MustFix is the CVSS score from which a finding is P1 (default 7.0, "high or critical").
	MustFix float64 `json:"mustFix"`
	// Warn is the CVSS score from which a finding is P2 (default 4.0, "medium").
	Warn float64 `json:"warn"`
	// SeverityFallback is used when no CVSS rating is usable (same defaults as the engine).
	SeverityFallback SeverityFallback `json:"severityFallback"`
}

// DefaultBaselineConfig returns the E2 baseline: CVSS ≥ 7.0 must be fixed.
func DefaultBaselineConfig() BaselineConfig {
	return BaselineConfig{MustFix: 7.0, Warn: 4.0, SeverityFallback: DefaultSeverityFallback()}
}

// Validate checks 0 < Warn < MustFix ≤ 10 and the fallback table.
func (c BaselineConfig) Validate() error {
	var errs []error
	if math.IsNaN(c.MustFix) || math.IsNaN(c.Warn) || !(c.Warn > 0 && c.Warn < c.MustFix && c.MustFix <= 10) {
		errs = append(errs, fmt.Errorf("thresholds want 0 < warn < mustFix ≤ 10, got warn=%v mustFix=%v", c.Warn, c.MustFix))
	}
	errs = append(errs, c.SeverityFallback.validate())
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("invalid baseline config: %w", err)
	}
	return nil
}

// Baseline is the CVSS-only scorer that Experiment E2 compares the engine against: Score is
// 10 × the selected CVSS base score (same version preference and severity fallback as the
// engine), and the tier comes from CVSS thresholds alone. EPSS, KEV, reachability, exposure
// and VEX are deliberately ignored. It is immutable and safe for concurrent use.
type Baseline struct {
	cfg BaselineConfig
}

var _ Scorer = (*Baseline)(nil)

// NewBaseline validates cfg and returns a baseline scorer.
func NewBaseline(cfg BaselineConfig) (*Baseline, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Baseline{cfg: cfg}, nil
}

// Score implements Scorer.
func (b *Baseline) Score(in Input) Result {
	cfg := b.cfg
	if cfg == (BaselineConfig{}) {
		cfg = DefaultBaselineConfig()
	}
	cv := selectCVSS(in, cfg.SeverityFallback)
	f := cv.factor(1)
	f.Contribution = round2(cv.score * 10)
	res := Result{
		FindingID: in.FindingID,
		VulnID:    in.VulnID,
		Scorer:    ScorerCVSSBaseline,
		Score:     round2(cv.score * 10),
		Factors:   []Factor{f},
	}
	if cv.estimated {
		res.Flags = append(res.Flags, FlagCVSSEstimated)
	}
	op := "<"
	switch {
	case cv.score >= cfg.MustFix:
		res.Tier, op = TierP1, "≥"
	case cv.score >= cfg.Warn:
		res.Tier = TierP2
	default:
		res.Tier = TierP3
	}
	res.Action = res.Tier.Action()
	res.Reason = fmt.Sprintf("%s (CVSS-only): %s %s %.1f", res.Tier, cvssPhrase(cv), op, cfg.MustFix)
	return res
}

// Rank returns a copy of results ordered for remediation: tier first (P1, P2, P3), then score
// descending. The sort is stable, so equal results keep their input order.
func Rank(results []Result) []Result {
	out := slices.Clone(results)
	slices.SortStableFunc(out, func(a, b Result) int {
		if d := a.Tier.order() - b.Tier.order(); d != 0 {
			return d
		}
		switch {
		case a.Score > b.Score:
			return -1
		case a.Score < b.Score:
			return 1
		default:
			return 0
		}
	})
	return out
}
