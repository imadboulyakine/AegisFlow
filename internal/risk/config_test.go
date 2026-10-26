package risk

import (
	"math"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/intel"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"weights over 1", func(c *Config) { c.Weights.KEV = 0.26 }, "sum to"},
		{"weights zero", func(c *Config) { c.Weights = Weights{} }, "sum to"},
		{"negative weight", func(c *Config) { c.Weights.EPSS = -0.1 }, "weights.epss"},
		{"nan weight", func(c *Config) { c.Weights.CVSS = math.NaN() }, "weights.cvss"},
		{"inf weight", func(c *Config) { c.Weights.KEV = math.Inf(1) }, "weights.kev"},
		{"reach order", func(c *Config) { c.Reachability.Imported = 0.8 }, "called ≥ unknown ≥ imported"},
		{"reach range", func(c *Config) { c.Reachability.Called = 1.5 }, "reachability.called"},
		{"reach nan", func(c *Config) { c.Reachability.Unknown = math.NaN() }, "reachability.unknown"},
		{"reach imported negative", func(c *Config) { c.Reachability.Imported = -1 }, "reachability.imported"},
		{"exposure order", func(c *Config) { c.Exposure.Build = 0.9 }, "internet ≥ internal ≥ build"},
		{"exposure range", func(c *Config) { c.Exposure.Internet = 2 }, "exposure.internet"},
		{"exposure internal", func(c *Config) { c.Exposure.Internal = -0.1 }, "exposure.internal"},
		{"exposure unknown", func(c *Config) { c.Exposure.Unknown = 1.1 }, "exposure.unknown"},
		{"fallback range", func(c *Config) { c.SeverityFallback.Unknown = 11 }, "severityFallback.unknown"},
		{"fallback order", func(c *Config) { c.SeverityFallback.Low = 9 }, "non-increasing from critical"},
		{"thresholds order", func(c *Config) { c.Thresholds = Thresholds{P1: 40, P2: 70} }, "0 < p2 < p1"},
		{"thresholds zero", func(c *Config) { c.Thresholds.P2 = 0 }, "0 < p2 < p1"},
		{"threshold range", func(c *Config) { c.Thresholds.P1 = 101 }, "thresholds.p1"},
		{"threshold nan", func(c *Config) { c.Thresholds.P2 = math.NaN() }, "thresholds.p2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.want)
			}
			if _, err := NewEngine(cfg); err == nil {
				t.Error("NewEngine accepted an invalid config")
			}
		})
	}

	// Multiple problems are reported together.
	cfg := DefaultConfig()
	cfg.Weights.CVSS, cfg.Exposure.Build = 2, 5
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "weights.cvss") || !strings.Contains(err.Error(), "exposure.build") {
		t.Errorf("joined errors = %v", err)
	}

	// The weight-sum tolerance absorbs float noise only.
	cfg = DefaultConfig()
	cfg.Weights.KEV += WeightSumTolerance / 10
	if err := cfg.Validate(); err != nil {
		t.Errorf("tolerance not applied: %v", err)
	}
	cfg.Weights.KEV += 1e-6
	if err := cfg.Validate(); err == nil {
		t.Error("sum 1+1e-6 accepted")
	}
}

func TestParseExposure(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]Exposure{"": ExposureUnknown, "Internet": ExposureInternet, "\tinternal\n": ExposureInternal, "BUILD": ExposureBuild, "unknown": ExposureUnknown} {
		got, err := ParseExposure(in)
		if err != nil || got != want {
			t.Errorf("ParseExposure(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseExposure("dmz"); err == nil {
		t.Error("ParseExposure(dmz) accepted")
	}
}

type stubSource map[string]intel.Intel

func (s stubSource) LookupAll(cves []string) intel.Intel {
	for _, c := range cves {
		if in, ok := s[c]; ok {
			return in
		}
	}
	return intel.Intel{KEVChecked: true}
}

func TestNewInput(t *testing.T) {
	t.Parallel()
	vuln := &evidence.Vulnerability{
		ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, Severity: evidence.SeverityCritical,
		CVSS: []evidence.CVSS{{Version: "3.1", BaseScore: 10}},
	}
	f := evidence.Finding{
		Kind: evidence.FindingVulnerability, Fingerprint: "fp-1", Severity: evidence.SeverityUnknown,
		Vulnerability: vuln, Reachability: evidence.ReachabilityCalled,
	}
	src := stubSource{"CVE-2021-44228": {CVE: "CVE-2021-44228", KEVChecked: true, KEV: true}}
	vex := &evidence.VEXStatement{VulnID: "CVE-2021-44228", Status: evidence.VEXAffected}
	in := NewInput(f, src, ExposureInternet, vex)
	if in.FindingID != "fp-1" || in.VulnID != vuln.ID || in.Severity != evidence.SeverityCritical || !in.Intel.KEV ||
		in.Reachability != evidence.ReachabilityCalled || in.Exposure != ExposureInternet || in.VEX != vex || len(in.CVSS) != 1 {
		t.Fatalf("input = %+v", in)
	}
	// Defensive copies: mutating the finding does not change the input.
	vuln.Aliases[0], vuln.CVSS[0].BaseScore = "CVE-0000-0000", 0
	if in.Aliases[0] != "CVE-2021-44228" || in.CVSS[0].BaseScore != 10 {
		t.Error("NewInput aliases the finding's slices")
	}
	if !in.matchesVuln(" cve-2021-44228 ") || in.matchesVuln("") || in.matchesVuln("CVE-2021-45046") {
		t.Error("matchesVuln wrong")
	}

	// Finding severity wins when known; no source means no intelligence.
	f.Severity = evidence.SeverityHigh
	if in := NewInput(f, nil, ExposureBuild, nil); in.Severity != evidence.SeverityHigh || in.Intel != (intel.Intel{}) {
		t.Errorf("input = %+v", in)
	}
	// Non-vulnerability findings score from severity alone.
	code := evidence.Finding{Kind: evidence.FindingCode, Fingerprint: "fp-2", Severity: evidence.SeverityMedium}
	in = NewInput(code, src, ExposureInternal, nil)
	res := mustEngine(t).Score(in)
	if in.VulnID != "" || !res.HasFlag(FlagCVSSEstimated) || res.Score != 9.24 { // 0.4·0.55 × 0.7 × 0.6
		t.Errorf("code finding: input %+v, score %v", in, res.Score)
	}
}
