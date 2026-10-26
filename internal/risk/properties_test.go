package risk

import (
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/intel"
)

const propertyIterations = 5000

var (
	reachLevels    = []evidence.Reachability{evidence.ReachabilityImported, evidence.ReachabilityUnknown, evidence.ReachabilityCalled} // ascending R
	exposureLevels = []Exposure{ExposureBuild, ExposureInternal, ExposureInternet}                                                     // ascending X
	allExposures   = []Exposure{ExposureBuild, ExposureInternal, ExposureInternet, ExposureUnknown}
	severities     = []evidence.Severity{"", evidence.SeverityUnknown, evidence.SeverityInfo, evidence.SeverityLow, evidence.SeverityMedium, evidence.SeverityHigh, evidence.SeverityCritical}
	cvssVersions   = []string{"2.0", "3.0", "3.1", "4.0"}
)

// randomInput draws a well-formed input (no VEX); about a quarter lack CVSS or EPSS.
func randomInput(r *rand.Rand) Input {
	in := Input{
		VulnID:       "CVE-2026-1000",
		Severity:     severities[r.IntN(len(severities))],
		Reachability: reachLevels[r.IntN(len(reachLevels))],
		Exposure:     allExposures[r.IntN(len(allExposures))],
		Intel:        intel.Intel{KEVChecked: r.IntN(4) != 0, KEV: r.IntN(3) == 0},
	}
	if r.IntN(4) != 0 {
		in.CVSS = []evidence.CVSS{{Version: cvssVersions[r.IntN(len(cvssVersions))], BaseScore: math.Round(r.Float64()*100) / 10}}
	}
	if r.IntN(4) != 0 {
		in.Intel.EPSSKnown, in.Intel.EPSS, in.Intel.Percentile = true, r.Float64(), r.Float64()
	}
	if in.Intel.KEV {
		in.Intel.KEVChecked, in.Intel.KEVDateAdded = true, time.Date(2025, 1, 1+r.IntN(300), 0, 0, 0, 0, time.UTC)
	}
	return in
}

// randomConfig draws a valid configuration with ordered multipliers.
func randomConfig(r *rand.Rand) Config {
	a, b, c := r.Float64(), r.Float64(), r.Float64()
	total := (a + b + c) / (0.5 + 0.5*r.Float64()) // sum in (0, 1]
	desc := func(n int) []float64 {
		v := make([]float64, n)
		for i := range v {
			v[i] = r.Float64()
		}
		slices.Sort(v)
		slices.Reverse(v)
		return v
	}
	rv, xv, fv := desc(3), desc(3), desc(5)
	p2 := 1 + r.Float64()*60
	return Config{
		Weights:          Weights{CVSS: a / total, EPSS: b / total, KEV: c / total},
		Reachability:     ReachabilityFactors{Called: rv[0], Unknown: rv[1], Imported: rv[2]},
		Exposure:         ExposureFactors{Internet: xv[0], Internal: xv[1], Build: xv[2], Unknown: r.Float64()},
		SeverityFallback: SeverityFallback{Critical: 10 * fv[0], High: 10 * fv[1], Medium: 10 * fv[2], Low: 10 * fv[3], Info: 10 * fv[4], Unknown: 10 * r.Float64()},
		Thresholds:       Thresholds{P2: p2, P1: p2 + 1 + r.Float64()*(99-p2)},
		KEVOverride:      r.IntN(2) == 0,
	}
}

// engines yields the default engine and random valid ones.
func engines(t *testing.T, r *rand.Rand, n int) []*Engine {
	t.Helper()
	out := []*Engine{mustEngine(t)}
	for range n {
		e, err := NewEngine(randomConfig(r))
		if err != nil {
			t.Fatalf("random config invalid: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func checkInvariants(t *testing.T, e *Engine, in Input, res Result) {
	t.Helper()
	if math.IsNaN(res.Score) || res.Score < 0 || res.Score > 100 {
		t.Fatalf("score %v out of [0,100] for %+v", res.Score, in)
	}
	if res.Score != round2(res.Score) {
		t.Fatalf("score %v not rounded to 2 dp", res.Score)
	}
	want := e.tier(res.Score)
	if res.HasFlag(FlagKEVOverride) {
		want = TierP1
	}
	if res.Tier != want || res.Action != res.Tier.Action() {
		t.Fatalf("tier %s/%s for score %v, want %s", res.Tier, res.Action, res.Score, want)
	}
	if res.Reason == "" || res.Reason[:2] != string(res.Tier) {
		t.Fatalf("reason %q does not start with the tier", res.Reason)
	}
	sum := 0.0
	for _, f := range res.Factors {
		if math.IsNaN(f.Contribution) || math.IsInf(f.Contribution, 0) {
			t.Fatalf("non-finite contribution in %+v", f)
		}
		sum += f.Contribution
	}
	if math.Abs(sum-res.Score) > 0.01*float64(len(res.Factors))+1e-9 {
		t.Fatalf("contributions sum to %v, score %v: %+v", sum, res.Score, res.Factors)
	}
}

func tierAtLeast(a, b Tier) bool { return a.order() <= b.order() }

func TestPropertyBoundsDeterminismInvariants(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(1, 2))
	for _, e := range engines(t, r, 20) {
		for range propertyIterations / 20 {
			in := randomInput(r)
			a, b := e.Score(in), e.Score(in)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("non-deterministic result:\n%+v\n%+v", a, b)
			}
			checkInvariants(t, e, in, a)
		}
	}
}

// TestPropertyMonotonic checks that raising any one input never lowers the score or the tier.
func TestPropertyMonotonic(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(3, 4))
	type step struct {
		name string
		up   func(Input) (lo, hi Input, ok bool)
	}
	steps := []step{
		{"S", func(in Input) (Input, Input, bool) {
			if len(in.CVSS) == 0 {
				return in, in, false
			}
			lo, hi := in, in
			x, y := r.Float64()*10, r.Float64()*10
			lo.CVSS = []evidence.CVSS{{Version: in.CVSS[0].Version, BaseScore: min(x, y)}}
			hi.CVSS = []evidence.CVSS{{Version: in.CVSS[0].Version, BaseScore: max(x, y)}}
			return lo, hi, true
		}},
		{"S fallback", func(in Input) (Input, Input, bool) {
			lo, hi := in, in
			lo.CVSS, hi.CVSS = nil, nil
			i, j := 2+r.IntN(5), 2+r.IntN(5) // info..critical, ordered by Rank
			lo.Severity, hi.Severity = severities[min(i, j)], severities[max(i, j)]
			return lo, hi, true
		}},
		{"E", func(in Input) (Input, Input, bool) {
			lo, hi := in, in
			x, y := r.Float64(), r.Float64()
			lo.Intel.EPSSKnown, lo.Intel.EPSS = r.IntN(3) != 0, min(x, y) // unknown counts as 0
			hi.Intel.EPSSKnown, hi.Intel.EPSS = true, max(x, y)
			if !lo.Intel.EPSSKnown {
				lo.Intel.EPSS = 0
			}
			return lo, hi, true
		}},
		{"K", func(in Input) (Input, Input, bool) {
			lo, hi := in, in
			lo.Intel.KEV, lo.Intel.KEVDateAdded = false, time.Time{}
			hi.Intel.KEV, hi.Intel.KEVChecked = true, true
			return lo, hi, true
		}},
		{"R", func(in Input) (Input, Input, bool) {
			lo, hi := in, in
			i, j := r.IntN(3), r.IntN(3)
			lo.Reachability, hi.Reachability = reachLevels[min(i, j)], reachLevels[max(i, j)]
			return lo, hi, true
		}},
		{"X", func(in Input) (Input, Input, bool) {
			lo, hi := in, in
			i, j := r.IntN(3), r.IntN(3)
			lo.Exposure, hi.Exposure = exposureLevels[min(i, j)], exposureLevels[max(i, j)]
			return lo, hi, true
		}},
	}
	for _, e := range engines(t, r, 20) {
		for range propertyIterations / 20 {
			base := randomInput(r)
			for _, s := range steps {
				lo, hi, ok := s.up(base)
				if !ok {
					continue
				}
				a, b := e.Score(lo), e.Score(hi)
				if b.Score < a.Score || !tierAtLeast(b.Tier, a.Tier) {
					t.Fatalf("not monotonic in %s: %v/%s -> %v/%s\nlo %+v\nhi %+v\ncfg %+v", s.name, a.Score, a.Tier, b.Score, b.Tier, lo, hi, e.Config())
				}
			}
		}
	}
}

func TestPropertyVEXSuppresses(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(5, 6))
	for _, e := range engines(t, r, 10) {
		for range propertyIterations / 10 {
			in := randomInput(r)
			st := &evidence.VEXStatement{VulnID: in.VulnID, Status: evidence.VEXFixed}
			if r.IntN(2) == 0 {
				st.Status, st.Justification = evidence.VEXNotAffected, "component_not_present"
			}
			in.VEX = st
			res := e.Score(in)
			if res.Score != 0 || res.Tier != TierP3 || !res.HasFlag(FlagVEXSuppressed) || res.HasFlag(FlagKEVOverride) {
				t.Fatalf("VEX %s not suppressing: %+v", st.Status, res)
			}
			checkInvariants(t, e, in, res)
		}
	}
}

func TestPropertyBaseline(t *testing.T) {
	t.Parallel()
	b, err := NewBaseline(DefaultBaselineConfig())
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(7, 8))
	for range propertyIterations {
		in := randomInput(r)
		res := b.Score(in)
		cv := selectCVSS(in, DefaultSeverityFallback())
		if res.Score != round2(cv.score*10) || res.Scorer != ScorerCVSSBaseline {
			t.Fatalf("baseline score %v for CVSS %v", res.Score, cv.score)
		}
		want := TierP3
		switch {
		case cv.score >= 7:
			want = TierP1
		case cv.score >= 4:
			want = TierP2
		}
		if res.Tier != want {
			t.Fatalf("baseline tier %s for CVSS %v", res.Tier, cv.score)
		}
		// Intelligence and context must not matter.
		other := in
		other.Intel, other.Reachability, other.Exposure = intel.Intel{KEV: true, EPSSKnown: true, EPSS: 1}, evidence.ReachabilityImported, ExposureBuild
		other.VEX = &evidence.VEXStatement{VulnID: in.VulnID, Status: evidence.VEXFixed}
		if got := b.Score(other); !reflect.DeepEqual(got, res) {
			t.Fatalf("baseline depends on non-CVSS inputs:\n%+v\n%+v", got, res)
		}
	}
}

func TestPropertyRank(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewPCG(9, 10))
	e := mustEngine(t)
	for range 200 {
		results := make([]Result, 1+r.IntN(30))
		for i := range results {
			results[i] = e.Score(randomInput(r))
			results[i].FindingID = string(rune('a' + i))
		}
		orig := slices.Clone(results)
		ranked := Rank(results)
		if !reflect.DeepEqual(results, orig) {
			t.Fatal("Rank mutated its input")
		}
		if len(ranked) != len(results) {
			t.Fatal("Rank changed the length")
		}
		pos := map[string]int{}
		for i, x := range results {
			pos[x.FindingID] = i
		}
		for i := 1; i < len(ranked); i++ {
			a, b := ranked[i-1], ranked[i]
			switch {
			case a.Tier.order() > b.Tier.order():
				t.Fatalf("tier order broken at %d: %s before %s", i, a.Tier, b.Tier)
			case a.Tier == b.Tier && a.Score < b.Score:
				t.Fatalf("score order broken at %d: %v before %v", i, a.Score, b.Score)
			case a.Tier == b.Tier && a.Score == b.Score && pos[a.FindingID] > pos[b.FindingID]:
				t.Fatalf("sort not stable at %d", i)
			}
		}
	}
	if got := Rank(nil); len(got) != 0 {
		t.Errorf("Rank(nil) = %v", got)
	}
}
