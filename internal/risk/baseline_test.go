package risk

import (
	"math"
	"strings"
	"testing"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

func TestBaselineScore(t *testing.T) {
	t.Parallel()
	b, err := NewBaseline(DefaultBaselineConfig())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		in     Input
		score  float64
		tier   Tier
		reason string
	}{
		{"must fix", Input{VulnID: "CVE-1", CVSS: v31(9.8), Intel: plainIntel(0.0001, 0.01), Reachability: evidence.ReachabilityImported, Exposure: ExposureBuild},
			98, TierP1, "P1 (CVSS-only): CVSS 9.8 ≥ 7.0"},
		{"threshold inclusive", Input{CVSS: v31(7.0)}, 70, TierP1, "P1 (CVSS-only): CVSS 7.0 ≥ 7.0"},
		{"warn", Input{CVSS: v31(6.9)}, 69, TierP2, "P2 (CVSS-only): CVSS 6.9 < 7.0"},
		{"low", Input{CVSS: v31(3.9)}, 39, TierP3, "P3 (CVSS-only): CVSS 3.9 < 7.0"},
		{"fallback", Input{Severity: evidence.SeverityCritical}, 95, TierP1, "P1 (CVSS-only): CVSS ~9.5 (estimated from critical severity) ≥ 7.0"},
	}
	for _, tt := range tests {
		res := b.Score(tt.in)
		if res.Score != tt.score || res.Tier != tt.tier || res.Reason != tt.reason || res.Scorer != ScorerCVSSBaseline || len(res.Factors) != 1 {
			t.Errorf("%s: %+v, want %v %s %q", tt.name, res, tt.score, tt.tier, tt.reason)
		}
	}
	if res := b.Score(Input{}); !res.HasFlag(FlagCVSSEstimated) || res.Score != 50 {
		t.Errorf("empty input = %+v", res)
	}
	var zero Baseline
	if got := zero.Score(Input{CVSS: v31(7)}); got.Tier != TierP1 {
		t.Errorf("zero baseline tier = %s", got.Tier)
	}
}

func TestBaselineConfigValidate(t *testing.T) {
	t.Parallel()
	bad := []BaselineConfig{
		{MustFix: 4, Warn: 7, SeverityFallback: DefaultSeverityFallback()},
		{MustFix: 11, Warn: 4, SeverityFallback: DefaultSeverityFallback()},
		{MustFix: math.NaN(), Warn: 4, SeverityFallback: DefaultSeverityFallback()},
		{MustFix: 7, Warn: 0, SeverityFallback: DefaultSeverityFallback()},
		{MustFix: 7, Warn: 4, SeverityFallback: SeverityFallback{Critical: -1}},
	}
	for i, c := range bad {
		if _, err := NewBaseline(c); err == nil || !strings.Contains(err.Error(), "invalid baseline config") {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

func TestRankOrder(t *testing.T) {
	t.Parallel()
	in := []Result{
		{FindingID: "a", Tier: TierP3, Score: 39},
		{FindingID: "b", Tier: TierP1, Score: 46.9}, // KEV override
		{FindingID: "c", Tier: TierP2, Score: 60},
		{FindingID: "d", Tier: TierP1, Score: 98},
		{FindingID: "e", Tier: TierP2, Score: 60},
		{FindingID: "f", Tier: "", Score: 99},
	}
	var got []string
	for _, r := range Rank(in) {
		got = append(got, r.FindingID)
	}
	if strings.Join(got, "") != "dbceaf" {
		t.Errorf("Rank order = %v, want d b c e a f", got)
	}
}
