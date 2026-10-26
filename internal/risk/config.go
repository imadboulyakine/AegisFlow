// Package risk is AegisFlow's explainable vulnerability risk-scoring engine (ADR-012,
// ARCHITECTURE.md §7):
//
//	risk = 100 × min(1, wS·S + wE·E + wK·K) × R × X × V
//
// S is the CVSS base score / 10 (v4.0 preferred, then v3.x, then v2.0, else an "estimated"
// value derived from the qualitative severity), E the EPSS probability (0 when unknown), K = 1
// when the CVE is in CISA KEV, R the reachability multiplier (called 1.0, unknown 0.7,
// imported 0.3), X the exposure multiplier (internet 1.0, internal 0.6, build 0.3) and V the
// VEX multiplier (0 for a valid not_affected or fixed statement, else 1). Tiers: P1 ≥ 70
// (block), P2 ≥ 40 (warn), P3 below (track). A finding that is in KEV, called and
// internet-facing is always P1 (the KEV override).
//
// Scoring is pure, deterministic and side-effect free. Every Result carries one Factor per
// term (raw value, normalized value, weight or multiplier, contribution in points, source and
// note) and a one-line human Reason, so the UI, the policy engine and Experiment E2 can show
// and audit why a finding ranks where it does. Baseline provides the CVSS-only comparison
// scorer used by E2.
package risk

import (
	"errors"
	"fmt"
	"math"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// WeightSumTolerance is how far the additive weights may exceed 1 (floating-point slack).
const WeightSumTolerance = 1e-9

// Weights are the coefficients of the additive part wS·S + wE·E + wK·K.
type Weights struct {
	CVSS float64 `json:"cvss"`
	EPSS float64 `json:"epss"`
	KEV  float64 `json:"kev"`
}

// Sum returns wS + wE + wK.
func (w Weights) Sum() float64 { return w.CVSS + w.EPSS + w.KEV }

// ReachabilityFactors are the R multipliers per reachability level.
type ReachabilityFactors struct {
	Called   float64 `json:"called"`
	Unknown  float64 `json:"unknown"`
	Imported float64 `json:"imported"`
}

// ExposureFactors are the X multipliers per deployment exposure.
type ExposureFactors struct {
	Internet float64 `json:"internet"`
	Internal float64 `json:"internal"`
	Build    float64 `json:"build"`
	// Unknown applies when the deployment context is not stated. The default (1.0) is
	// conservative: an unknown exposure is treated like an internet-facing one, but never
	// triggers the KEV override, which requires an explicit internet exposure.
	Unknown float64 `json:"unknown"`
}

// SeverityFallback gives the CVSS-scale (0..10) score assumed when a finding has no usable
// CVSS rating; results using it are flagged FlagCVSSEstimated.
type SeverityFallback struct {
	Critical float64 `json:"critical"`
	High     float64 `json:"high"`
	Medium   float64 `json:"medium"`
	Low      float64 `json:"low"`
	Info     float64 `json:"info"`
	Unknown  float64 `json:"unknown"`
}

// Thresholds are the minimum scores (0..100) of tiers P1 and P2.
type Thresholds struct {
	P1 float64 `json:"p1"`
	P2 float64 `json:"p2"`
}

// Config parameterizes the Engine. Start from DefaultConfig; weights are initial estimates to
// be calibrated in Experiment E2 and frozen before the final evaluation (ADR-012).
type Config struct {
	Weights          Weights             `json:"weights"`
	Reachability     ReachabilityFactors `json:"reachability"`
	Exposure         ExposureFactors     `json:"exposure"`
	SeverityFallback SeverityFallback    `json:"severityFallback"`
	Thresholds       Thresholds          `json:"thresholds"`
	// KEVOverride enables "in KEV + called + internet-facing ⇒ P1 regardless of score".
	KEVOverride bool `json:"kevOverride"`
}

// DefaultConfig returns the ADR-012 parameters.
func DefaultConfig() Config {
	return Config{
		Weights:          Weights{CVSS: 0.40, EPSS: 0.35, KEV: 0.25},
		Reachability:     ReachabilityFactors{Called: 1.0, Unknown: 0.7, Imported: 0.3},
		Exposure:         ExposureFactors{Internet: 1.0, Internal: 0.6, Build: 0.3, Unknown: 1.0},
		SeverityFallback: DefaultSeverityFallback(),
		Thresholds:       Thresholds{P1: 70, P2: 40},
		KEVOverride:      true,
	}
}

// DefaultSeverityFallback returns the CVSS-scale scores assumed per qualitative severity:
// the midpoints of the CVSS v3 bands (critical 9.5, high 8.0, medium 5.5), low rounded up to
// 2.5, info mapped to "None" (0.0) and unknown to a neutral 5.0.
func DefaultSeverityFallback() SeverityFallback {
	return SeverityFallback{Critical: 9.5, High: 8.0, Medium: 5.5, Low: 2.5, Info: 0.0, Unknown: 5.0}
}

// Validate checks that every parameter is finite and in range, that the weights are
// non-negative with 0 < sum ≤ 1 + WeightSumTolerance, and that multipliers and fallbacks are
// ordered (called ≥ unknown ≥ imported, internet ≥ internal ≥ build, critical ≥ … ≥ info), which
// keeps the score monotonic in every input. All problems are reported together.
func (c Config) Validate() error {
	var errs []error
	check := func(name string, v, lo, hi float64) {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < lo || v > hi {
			errs = append(errs, fmt.Errorf("%s = %v, want a number in [%v, %v]", name, v, lo, hi))
		}
	}
	order := func(names string, vs ...float64) {
		for i := 1; i < len(vs); i++ {
			if vs[i] > vs[i-1] {
				errs = append(errs, fmt.Errorf("%s must be non-increasing, got %v", names, vs))
				return
			}
		}
	}

	w := c.Weights
	check("weights.cvss", w.CVSS, 0, 1)
	check("weights.epss", w.EPSS, 0, 1)
	check("weights.kev", w.KEV, 0, 1)
	if s := w.Sum(); !(s > 0) || s > 1+WeightSumTolerance {
		errs = append(errs, fmt.Errorf("weights sum to %v, want 0 < sum ≤ 1", s))
	}

	r := c.Reachability
	check("reachability.called", r.Called, 0, 1)
	check("reachability.unknown", r.Unknown, 0, 1)
	check("reachability.imported", r.Imported, 0, 1)
	order("reachability called ≥ unknown ≥ imported", r.Called, r.Unknown, r.Imported)

	x := c.Exposure
	check("exposure.internet", x.Internet, 0, 1)
	check("exposure.internal", x.Internal, 0, 1)
	check("exposure.build", x.Build, 0, 1)
	check("exposure.unknown", x.Unknown, 0, 1)
	order("exposure internet ≥ internal ≥ build", x.Internet, x.Internal, x.Build)

	errs = append(errs, c.SeverityFallback.validate())

	t := c.Thresholds
	check("thresholds.p1", t.P1, 0, 100)
	check("thresholds.p2", t.P2, 0, 100)
	if !(t.P2 > 0 && t.P2 < t.P1) {
		errs = append(errs, fmt.Errorf("thresholds want 0 < p2 < p1 ≤ 100, got p2=%v p1=%v", t.P2, t.P1))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("invalid risk config: %w", err)
	}
	return nil
}

func (f SeverityFallback) validate() error {
	var errs []error
	for _, p := range []struct {
		name string
		v    float64
	}{{"critical", f.Critical}, {"high", f.High}, {"medium", f.Medium}, {"low", f.Low}, {"info", f.Info}, {"unknown", f.Unknown}} {
		if math.IsNaN(p.v) || math.IsInf(p.v, 0) || p.v < 0 || p.v > 10 {
			errs = append(errs, fmt.Errorf("severityFallback.%s = %v, want a number in [0, 10]", p.name, p.v))
		}
	}
	vs := []float64{f.Critical, f.High, f.Medium, f.Low, f.Info}
	for i := 1; i < len(vs); i++ {
		if vs[i] > vs[i-1] {
			errs = append(errs, fmt.Errorf("severityFallback must be non-increasing from critical to info, got %v", vs))
			break
		}
	}
	return errors.Join(errs...)
}

// forSeverity returns the fallback score for a qualitative severity.
func (f SeverityFallback) forSeverity(s evidence.Severity) float64 {
	switch s {
	case evidence.SeverityCritical:
		return f.Critical
	case evidence.SeverityHigh:
		return f.High
	case evidence.SeverityMedium:
		return f.Medium
	case evidence.SeverityLow:
		return f.Low
	case evidence.SeverityInfo:
		return f.Info
	default:
		return f.Unknown
	}
}
