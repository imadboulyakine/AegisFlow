package risk

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/intel"
)

// FuzzScore feeds arbitrary (including invalid) values through the engine and the baseline:
// they must never panic and must keep every invariant.
func FuzzScore(f *testing.F) {
	f.Add(9.8, "3.1", "critical", 0.94, 0.97, true, true, true, "called", "internet", "", "", "CVE-2026-0001")
	f.Add(5.3, "4.0", "medium", 0.02, 0.8, true, true, true, "called", "internet", "not_affected", "component_not_present", "cve-2026-0001")
	f.Add(-1.0, "9", "SEVERE", -0.5, 2.0, true, false, false, "maybe", "dmz", "fixed", "", "CVE-2026-0001")
	f.Add(11.0, "CVSS:3.0", "", 1.0, 1.0, false, false, true, "", "", "bogus", "\n", "")
	f.Fuzz(func(t *testing.T, cvss float64, version, severity string, epss, pct float64, epssKnown, kev, kevChecked bool,
		reach, exposure, vexStatus, justification, vexID string) {
		in := Input{
			FindingID:    "fuzz",
			VulnID:       "CVE-2026-0001",
			CVSS:         []evidence.CVSS{{Version: version, BaseScore: cvss}},
			Severity:     evidence.Severity(severity),
			Intel:        intel.Intel{EPSSKnown: epssKnown, EPSS: epss, Percentile: pct, KEV: kev, KEVChecked: kevChecked || kev, KEVDateAdded: time.Unix(0, 0)},
			Reachability: evidence.Reachability(reach),
			Exposure:     Exposure(exposure),
		}
		if vexStatus != "" {
			in.VEX = &evidence.VEXStatement{VulnID: vexID, Status: evidence.VEXStatus(vexStatus), Justification: justification, Author: justification}
		}
		e := mustEngine(t)
		res := e.Score(in)
		checkInvariants(t, e, in, res)
		if again := e.Score(in); !reflect.DeepEqual(res, again) {
			t.Fatal("non-deterministic")
		}
		if strings.ContainsAny(res.Reason, "\n\r") {
			t.Fatalf("multi-line reason %q", res.Reason)
		}
		for _, fct := range res.Factors {
			if strings.ContainsAny(fct.Note+fct.Source+fct.Raw, "\n\r") {
				t.Fatalf("multi-line factor text %+v", fct)
			}
		}
		if res.HasFlag(FlagVEXSuppressed) != (res.Score == 0 && in.VEX != nil && res.Factors[5].Normalized == 0) {
			t.Fatalf("suppression flag inconsistent: %+v", res)
		}

		b, err := NewBaseline(DefaultBaselineConfig())
		if err != nil {
			t.Fatal(err)
		}
		br := b.Score(in)
		if br.Score < 0 || br.Score > 100 || br.Tier == "" {
			t.Fatalf("baseline result %+v", br)
		}
		ranked := Rank([]Result{br, res})
		if len(ranked) != 2 || ranked[0].Tier.order() > ranked[1].Tier.order() {
			t.Fatalf("rank %+v", ranked)
		}
	})
}
