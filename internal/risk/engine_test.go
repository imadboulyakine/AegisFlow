package risk

import (
	"bytes"
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/intel"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

func mustEngine(tb testing.TB) *Engine {
	tb.Helper()
	e, err := NewEngine(DefaultConfig())
	if err != nil {
		tb.Fatal(err)
	}
	return e
}

func day(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err) // test-only helper with literal input
	}
	return d
}

func v31(score float64) []evidence.CVSS {
	return []evidence.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: score}}
}

// kevIntel is intelligence for a CVE that is in KEV with the given EPSS.
func kevIntel(epss, pct float64, added string) intel.Intel {
	return intel.Intel{CVE: "CVE-2026-0001", EPSSKnown: true, EPSS: epss, Percentile: pct, ScoreDate: day("2026-10-25"),
		ModelVersion: "v2025.03.14", KEVChecked: true, KEV: true, KEVDateAdded: day(added)}
}

// plainIntel is intelligence for a CVE that is not in KEV.
func plainIntel(epss, pct float64) intel.Intel {
	return intel.Intel{CVE: "CVE-2026-0002", EPSSKnown: true, EPSS: epss, Percentile: pct, ScoreDate: day("2026-10-25"),
		ModelVersion: "v2025.03.14", KEVChecked: true}
}

func notAffected(id, justification string) *evidence.VEXStatement {
	return &evidence.VEXStatement{VulnID: id, Status: evidence.VEXNotAffected, Justification: justification,
		Author: "security@example.com", Timestamp: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
}

type goldenCase struct {
	name   string
	in     Input
	score  float64
	tier   Tier
	flags  []Flag
	reason string
}

func goldenCases() []goldenCase {
	log4j := intel.Intel{CVE: "CVE-2021-44228", EPSSKnown: true, EPSS: 0.94401, Percentile: 0.99997, ScoreDate: day("2026-10-25"),
		ModelVersion: "v2025.03.14", KEVChecked: true, KEV: true, KEVDateAdded: day("2021-12-10"), KEVDueDate: day("2021-12-24"), KEVRansomware: true}
	return []goldenCase{
		{
			name:   "brief example",
			in:     Input{FindingID: "f1", VulnID: "CVE-2026-0001", CVSS: v31(9.8), Intel: kevIntel(0.94, 0.97, "2026-03-02"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  97.1, // 100 × (0.4·0.98 + 0.35·0.94 + 0.25·1) = 97.1
			tier:   TierP1,
			flags:  []Flag{FlagKEVOverride},
			reason: "P1: CVSS 9.8, EPSS 0.94 (97th pct), in CISA KEV since 2026-03-02, reachable (called), internet-facing",
		},
		{
			name:   "log4shell",
			in:     Input{FindingID: "f2", VulnID: "CVE-2021-44228", CVSS: []evidence.CVSS{{Version: "3.1", BaseScore: 10}}, Intel: log4j, Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  98.04, // 0.4 + 0.3304035 + 0.25 = 0.9804035
			tier:   TierP1,
			flags:  []Flag{FlagKEVOverride},
			reason: "P1: CVSS 10.0, EPSS 0.94 (99th pct), in CISA KEV since 2021-12-10 (ransomware use), reachable (called), internet-facing",
		},
		{
			name:   "KEV override raises P2",
			in:     Input{VulnID: "CVE-2026-0001", CVSS: v31(5.3), Intel: kevIntel(0.02, 0.8, "2026-01-15"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  46.9, // 0.212 + 0.007 + 0.25 = 0.469
			tier:   TierP1,
			flags:  []Flag{FlagKEVOverride},
			reason: "P1 (KEV override): CVSS 5.3, EPSS 0.02 (80th pct), in CISA KEV since 2026-01-15, reachable (called), internet-facing",
		},
		{
			name:   "KEV but internal: no override",
			in:     Input{VulnID: "CVE-2026-0001", CVSS: v31(5.3), Intel: kevIntel(0.02, 0.8, "2026-01-15"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternal},
			score:  28.14, // 0.469 × 0.6
			tier:   TierP3,
			reason: "P3: CVSS 5.3, EPSS 0.02 (80th pct), in CISA KEV since 2026-01-15, reachable (called), internal",
		},
		{
			name:   "critical CVSS, unreachable, build-only",
			in:     Input{VulnID: "CVE-2026-0002", CVSS: v31(9.8), Intel: plainIntel(0.001, 0.3), Reachability: evidence.ReachabilityImported, Exposure: ExposureBuild},
			score:  3.53, // (0.392 + 0.00035) × 0.3 × 0.3 = 0.0353115
			tier:   TierP3,
			reason: "P3: CVSS 9.8, EPSS 0.001 (30th pct), not in CISA KEV, not called (imported only), build/dev-only",
		},
		{
			name:   "high EPSS without KEV reaches P1",
			in:     Input{VulnID: "CVE-2026-0002", CVSS: v31(9.8), Intel: plainIntel(0.97, 0.999), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  73.15, // 0.392 + 0.3395
			tier:   TierP1,
			reason: "P1: CVSS 9.8, EPSS 0.97 (99th pct), not in CISA KEV, reachable (called), internet-facing",
		},
		{
			name:   "nothing known: severity fallback",
			in:     Input{VulnID: "GHSA-aaaa-bbbb-cccc", Severity: evidence.SeverityHigh},
			score:  22.4, // 0.4·0.8 × 0.7 (reachability unknown) × 1.0 (exposure unknown)
			tier:   TierP3,
			flags:  []Flag{FlagCVSSEstimated, FlagEPSSUnknown, FlagKEVUnchecked, FlagExposureUnknown},
			reason: "P3: CVSS ~8.0 (estimated from high severity), EPSS unknown, KEV not checked, reachability unknown, exposure unknown",
		},
		{
			name:   "P2 boundary is inclusive",
			in:     Input{VulnID: "CVE-2026-0002", CVSS: v31(10), Intel: plainIntel(0, 0), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  40,
			tier:   TierP2,
			reason: "P2: CVSS 10.0, EPSS 0 (0th pct), not in CISA KEV, reachable (called), internet-facing",
		},
		{
			name:   "just below P2",
			in:     Input{VulnID: "CVE-2026-0002", CVSS: v31(9.9), Intel: plainIntel(0, 0), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  39.6,
			tier:   TierP3,
			reason: "P3: CVSS 9.9, EPSS 0 (0th pct), not in CISA KEV, reachable (called), internet-facing",
		},
		{
			name:   "rounds to 70.00 and is P1",
			in:     Input{VulnID: "CVE-2026-0002", CVSS: v31(10), Intel: plainIntel(0.857142857, 0.99), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  70,
			tier:   TierP1,
			reason: "P1: CVSS 10.0, EPSS 0.86 (99th pct), not in CISA KEV, reachable (called), internet-facing",
		},
		{
			name:   "internal, reachability unknown",
			in:     Input{VulnID: "CVE-2026-0002", CVSS: v31(7.5), Intel: plainIntel(0.5, 0.95), Exposure: ExposureInternal},
			score:  19.95, // (0.3 + 0.175) × 0.7 × 0.6
			tier:   TierP3,
			reason: "P3: CVSS 7.5, EPSS 0.50 (95th pct), not in CISA KEV, reachability unknown, internal",
		},
		{
			name: "CVSS v4 preferred over higher v3.1",
			in: Input{VulnID: "CVE-2026-0002", CVSS: []evidence.CVSS{{Version: "3.1", BaseScore: 9.8}, {Version: "4.0", Vector: "CVSS:4.0/AV:N", BaseScore: 9.3}},
				Intel: plainIntel(0, 0), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  37.2,
			tier:   TierP3,
			reason: "P3: CVSS 9.3, EPSS 0 (0th pct), not in CISA KEV, reachable (called), internet-facing",
		},
		{
			name: "highest of the v3 family, v2 ignored",
			in: Input{VulnID: "CVE-2026-0002", CVSS: []evidence.CVSS{{Version: "2.0", BaseScore: 10}, {Version: "3.0", BaseScore: 7.5}, {Version: "CVSS:3.1", BaseScore: 8.1}},
				Intel: plainIntel(0, 0), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  32.4,
			tier:   TierP3,
			reason: "P3: CVSS 8.1, EPSS 0 (0th pct), not in CISA KEV, reachable (called), internet-facing",
		},
		{
			name: "invalid ratings fall back to severity",
			in: Input{VulnID: "CVE-2026-0002", Severity: "MODERATE", CVSS: []evidence.CVSS{{Version: "5.0", BaseScore: 9}, {Version: "3.1", BaseScore: 11}, {Version: "3.1", BaseScore: math.NaN()}},
				Intel: plainIntel(0, 0), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet},
			score:  22,
			tier:   TierP3,
			flags:  []Flag{FlagCVSSEstimated},
			reason: "P3: CVSS ~5.5 (estimated from medium severity), EPSS 0 (0th pct), not in CISA KEV, reachable (called), internet-facing",
		},
		{
			name: "VEX not_affected suppresses",
			in: Input{VulnID: "CVE-2026-0001", Aliases: []string{"GHSA-1111-2222-3333"}, CVSS: v31(9.8), Intel: kevIntel(0.9, 0.99, "2026-03-02"),
				Reachability: evidence.ReachabilityImported, Exposure: ExposureInternet, VEX: notAffected("ghsa-1111-2222-3333", "vulnerable_code_not_in_execute_path")},
			score:  0,
			tier:   TierP3,
			flags:  []Flag{FlagVEXSuppressed},
			reason: "P3: suppressed by VEX not_affected (vulnerable_code_not_in_execute_path); CVSS 9.8, EPSS 0.90 (99th pct), in CISA KEV since 2026-03-02, not called (imported only), internet-facing",
		},
		{
			name: "VEX fixed beats KEV override but flags the conflict",
			in: Input{VulnID: "CVE-2026-0001", CVSS: v31(9.8), Intel: kevIntel(0.9, 0.99, "2026-03-02"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet,
				VEX: &evidence.VEXStatement{VulnID: "CVE-2026-0001", Status: evidence.VEXFixed}},
			score:  0,
			tier:   TierP3,
			flags:  []Flag{FlagVEXSuppressed, FlagVEXConflict},
			reason: "P3: suppressed by VEX fixed; CVSS 9.8, EPSS 0.90 (99th pct), in CISA KEV since 2026-03-02, reachable (called), internet-facing, VEX contradicts call-graph evidence",
		},
		{
			name: "VEX not_affected without justification is ignored",
			in: Input{VulnID: "CVE-2026-0002", CVSS: v31(9.8), Intel: plainIntel(0.97, 0.999), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet,
				VEX: notAffected("CVE-2026-0002", "")},
			score:  73.15,
			tier:   TierP1,
			flags:  []Flag{FlagVEXIgnored},
			reason: "P1: CVSS 9.8, EPSS 0.97 (99th pct), not in CISA KEV, reachable (called), internet-facing, VEX statement ignored",
		},
		{
			name: "VEX for another vulnerability is ignored",
			in: Input{VulnID: "CVE-2026-0002", CVSS: v31(9.8), Intel: plainIntel(0.97, 0.999), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet,
				VEX: notAffected("CVE-2026-9999", "component_not_present")},
			score:  73.15,
			tier:   TierP1,
			flags:  []Flag{FlagVEXIgnored},
			reason: "P1: CVSS 9.8, EPSS 0.97 (99th pct), not in CISA KEV, reachable (called), internet-facing, VEX statement ignored",
		},
		{
			name: "VEX affected keeps the score",
			in: Input{VulnID: "CVE-2026-0002", CVSS: v31(9.8), Intel: plainIntel(0.5, 0.9), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet,
				VEX: &evidence.VEXStatement{VulnID: "CVE-2026-0002", Status: evidence.VEXAffected}},
			score:  56.7,
			tier:   TierP2,
			reason: "P2: CVSS 9.8, EPSS 0.50 (90th pct), not in CISA KEV, reachable (called), internet-facing, VEX affected",
		},
	}
}

func TestEngineGolden(t *testing.T) {
	t.Parallel()
	e := mustEngine(t)
	var all []Result
	for _, tc := range goldenCases() {
		res := e.Score(tc.in)
		all = append(all, res)
		if res.Score != tc.score || res.Tier != tc.tier || res.Action != tc.tier.Action() {
			t.Errorf("%s: score %v tier %s, want %v %s", tc.name, res.Score, res.Tier, tc.score, tc.tier)
		}
		if !slices.Equal(res.Flags, tc.flags) {
			t.Errorf("%s: flags %v, want %v", tc.name, res.Flags, tc.flags)
		}
		if res.Reason != tc.reason {
			t.Errorf("%s: reason\n got %q\nwant %q", tc.name, res.Reason, tc.reason)
		}
		if res.Scorer != ScorerRisk || res.FindingID != tc.in.FindingID || res.VulnID != tc.in.VulnID {
			t.Errorf("%s: identity %q %q %q", tc.name, res.Scorer, res.FindingID, res.VulnID)
		}
	}

	// The full explanations are pinned in a golden file so format changes are reviewed.
	got, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "golden_results.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run go test -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("results differ from %s; run go test ./internal/risk -run TestEngineGolden -update and review the diff", golden)
	}
}

func TestEngineFactors(t *testing.T) {
	t.Parallel()
	e := mustEngine(t)
	res := e.Score(Input{VulnID: "CVE-2026-0002", CVSS: v31(9.8), Intel: plainIntel(0.001, 0.3), Reachability: evidence.ReachabilityImported, Exposure: ExposureBuild})
	want := []Factor{
		{Name: FactorCVSS, Kind: KindAdditive, Raw: "9.8", Normalized: 0.98, Weight: 0.4, Contribution: 39.2, Source: "CVSS v3.1", Note: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Name: FactorEPSS, Kind: KindAdditive, Raw: "0.001", Normalized: 0.001, Weight: 0.35, Contribution: 0.04, Source: "EPSS (model v2025.03.14, 2026-10-25)", Note: "percentile 0.3"},
		{Name: FactorKEV, Kind: KindAdditive, Raw: "false", Normalized: 0, Weight: 0.25, Contribution: 0, Source: "CISA KEV", Note: "not listed"},
		{Name: FactorReachability, Kind: KindMultiplier, Raw: "imported", Normalized: 0.3, Weight: 0.3, Contribution: -27.46, Source: "reachability analysis", Note: "vulnerable package present but not called"},
		{Name: FactorExposure, Kind: KindMultiplier, Raw: "build", Normalized: 0.3, Weight: 0.3, Contribution: -8.24, Source: "deployment context"},
		{Name: FactorVEX, Kind: KindMultiplier, Raw: "none", Normalized: 1, Weight: 1, Contribution: 0, Source: "VEX", Note: "no VEX statement"},
	}
	if !slices.Equal(res.Factors, want) {
		for i := range max(len(res.Factors), len(want)) {
			var g, w Factor
			if i < len(res.Factors) {
				g = res.Factors[i]
			}
			if i < len(want) {
				w = want[i]
			}
			if g != w {
				t.Errorf("factor %d:\n got %+v\nwant %+v", i, g, w)
			}
		}
	}
	if f, ok := res.Factor(FactorReachability); !ok || f.Raw != "imported" {
		t.Errorf("Factor lookup = %+v %v", f, ok)
	}
	if _, ok := res.Factor(FactorOverride); ok {
		t.Error("unexpected override factor")
	}
}

func TestEngineOverrideAndVEXFactors(t *testing.T) {
	t.Parallel()
	e := mustEngine(t)
	res := e.Score(Input{VulnID: "CVE-2026-0001", CVSS: v31(5.3), Intel: kevIntel(0.02, 0.8, "2026-01-15"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet})
	of, ok := res.Factor(FactorOverride)
	if !ok || of.Kind != KindOverride || of.Contribution != 0 || of.Note != "tier raised from P2 to P1" {
		t.Errorf("override factor = %+v", of)
	}
	if kf, _ := res.Factor(FactorKEV); kf.Note != "exploited in the wild; added 2026-01-15" || kf.Contribution != 25 {
		t.Errorf("kev factor = %+v", kf)
	}

	in := Input{VulnID: "CVE-2026-0001", CVSS: v31(9.8), Intel: kevIntel(0.9, 0.99, "2026-03-02"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet,
		VEX: &evidence.VEXStatement{VulnID: "CVE-2026-0001", Status: evidence.VEXNotAffected, ImpactStatement: "mitigated\nby\tWAF rule 12", Author: "psirt", Timestamp: time.Date(2026, 10, 20, 9, 0, 0, 0, time.FixedZone("CET", 3600))}}
	res = e.Score(in)
	vf, _ := res.Factor(FactorVEX)
	if vf.Source != "VEX by psirt at 2026-10-20T08:00:00Z" {
		t.Errorf("vex source = %q", vf.Source)
	}
	for _, want := range []string{"suppressed by VEX not_affected", "impact: mitigated by WAF rule 12", "conflicts with reachability=called", "KEV override (KEV + called + internet) not applied"} {
		if !strings.Contains(vf.Note, want) {
			t.Errorf("vex note %q lacks %q", vf.Note, want)
		}
	}
	if _, ok := res.Factor(FactorOverride); ok || res.Tier != TierP3 || res.Score != 0 {
		t.Errorf("suppressed result = %+v", res)
	}
	// Contributions of a suppressed finding still account for the full drop to 0.
	sum := 0.0
	for _, f := range res.Factors {
		sum += f.Contribution
	}
	if math.Abs(sum) > 0.05 {
		t.Errorf("contributions sum to %v, want ≈ 0", sum)
	}

	in.VEX.Status = "bogus"
	if res := e.Score(in); !res.HasFlag(FlagVEXIgnored) || res.Tier != TierP1 {
		t.Errorf("unknown VEX status: %+v", res)
	}
	in.VEX.Status, in.VulnID = evidence.VEXFixed, ""
	if res := e.Score(in); !res.HasFlag(FlagVEXIgnored) {
		t.Errorf("VEX applied without vulnerability identity: %+v", res.Flags)
	}
}

func TestEngineUnrecognisedLevelsAndInvalidIntel(t *testing.T) {
	t.Parallel()
	e := mustEngine(t)
	bad := intel.Intel{EPSSKnown: true, EPSS: math.NaN(), Percentile: 2, KEVChecked: true}
	res := e.Score(Input{CVSS: v31(5), Intel: bad, Reachability: "maybe", Exposure: "dmz"})
	if !res.HasFlag(FlagEPSSUnknown) || !res.HasFlag(FlagExposureUnknown) {
		t.Errorf("flags = %v", res.Flags)
	}
	rf, _ := res.Factor(FactorReachability)
	xf, _ := res.Factor(FactorExposure)
	ef, _ := res.Factor(FactorEPSS)
	if rf.Raw != "unknown" || !strings.Contains(rf.Note, `"maybe"`) || xf.Raw != "unknown" || !strings.Contains(xf.Note, `"dmz"`) || !strings.Contains(ef.Note, "invalid") {
		t.Errorf("factors = %+v / %+v / %+v", rf, xf, ef)
	}
	if res.Score != 14 { // 0.2 × 0.7 × 1.0
		t.Errorf("score = %v, want 14", res.Score)
	}
	// Valid EPSS with an invalid percentile: score used, percentile omitted.
	res = e.Score(Input{CVSS: v31(5), Intel: intel.Intel{EPSSKnown: true, EPSS: 0.5, Percentile: math.Inf(1)}})
	if ef, _ := res.Factor(FactorEPSS); ef.Note != "" || !strings.Contains(res.Reason, "EPSS 0.50,") {
		t.Errorf("epss factor %+v, reason %q", ef, res.Reason)
	}
}

func TestZeroEngineUsesDefaults(t *testing.T) {
	t.Parallel()
	in := goldenCases()[0].in
	var zero Engine
	if got, want := zero.Score(in), mustEngine(t).Score(in); got.Score != want.Score || got.Tier != want.Tier || got.Reason != want.Reason {
		t.Errorf("zero engine = %+v, want %+v", got, want)
	}
}

func TestEngineConfigAndDisabledOverride(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.KEVOverride = false
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e.Config() != cfg {
		t.Error("Config() does not round-trip")
	}
	res := e.Score(Input{VulnID: "CVE-2026-0001", CVSS: v31(5.3), Intel: kevIntel(0.02, 0.8, "2026-01-15"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet})
	if res.Tier != TierP2 || res.HasFlag(FlagKEVOverride) {
		t.Errorf("override disabled: %+v", res)
	}
}

func TestEngineCappedSum(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Weights = Weights{CVSS: 0.5, EPSS: 0.25, KEV: 0.25 + WeightSumTolerance/2}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res := e.Score(Input{CVSS: v31(10), Intel: kevIntel(1, 1, "2026-01-01"), Reachability: evidence.ReachabilityCalled, Exposure: ExposureInternet})
	if res.Score != 100 {
		t.Errorf("score = %v, want 100 (capped)", res.Score)
	}
	sum := 0.0
	for _, f := range res.Factors[:3] {
		sum += f.Contribution
	}
	if math.Abs(sum-100) > 0.02 {
		t.Errorf("additive contributions sum to %v, want 100", sum)
	}
}

func TestTierAction(t *testing.T) {
	t.Parallel()
	for tier, want := range map[Tier]Action{TierP1: ActionBlock, TierP2: ActionWarn, TierP3: ActionTrack, "P9": ActionTrack} {
		if got := tier.Action(); got != want {
			t.Errorf("%s.Action() = %s, want %s", tier, got, want)
		}
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()
	for in, want := range map[int]string{0: "0th", 1: "1st", 2: "2nd", 3: "3rd", 4: "4th", 11: "11th", 12: "12th", 13: "13th", 21: "21st", 22: "22nd", 23: "23rd", 97: "97th", 100: "100th", 250: "100th", -5: "0th"} {
		if got := ordinal(in); got != want {
			t.Errorf("ordinal(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[float64]string{0: "0", 0.94401: "0.94", 0.01: "0.01", 0.00087: "0.00087", 1: "1.00"} {
		if got := formatProb(in); got != want {
			t.Errorf("formatProb(%v) = %q, want %q", in, got, want)
		}
	}
	cleanCases := []struct {
		in   string
		max  int
		want string
	}{
		{"  a\n\tb  ", 10, "a b"},
		{"x\u2028y\x7fz", 10, "x y z"},
		{strings.Repeat("é", 10), 4, "éééé…"},
		{"bad\xffutf8", 20, "bad\uFFFDutf8"},
	}
	for _, tc := range cleanCases {
		if got := clean(tc.in, tc.max); got != tc.want {
			t.Errorf("clean(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
	if round2(-0.001) != 0 || math.Signbit(round2(-0.001)) {
		t.Error("round2 keeps negative zero")
	}
}
