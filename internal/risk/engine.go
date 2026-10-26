package risk

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
	"github.com/imadboulyakine/aegisflow/internal/intel"
)

// Tier is the remediation priority of a finding.
type Tier string

// Tiers (ADR-012).
const (
	TierP1 Tier = "P1" // score ≥ P1 threshold (70) or KEV override: block
	TierP2 Tier = "P2" // score ≥ P2 threshold (40): warn
	TierP3 Tier = "P3" // below: track
)

// Action is the gate behaviour associated with a tier.
type Action string

// Actions.
const (
	ActionBlock Action = "block"
	ActionWarn  Action = "warn"
	ActionTrack Action = "track"
)

// Action returns the gate behaviour of the tier.
func (t Tier) Action() Action {
	switch t {
	case TierP1:
		return ActionBlock
	case TierP2:
		return ActionWarn
	default:
		return ActionTrack
	}
}

// order sorts tiers P1 < P2 < P3 < anything else.
func (t Tier) order() int {
	switch t {
	case TierP1:
		return 1
	case TierP2:
		return 2
	case TierP3:
		return 3
	default:
		return 4
	}
}

// Factor names, in the order they appear in Result.Factors.
const (
	FactorCVSS         = "cvss"
	FactorEPSS         = "epss"
	FactorKEV          = "kev"
	FactorReachability = "reachability"
	FactorExposure     = "exposure"
	FactorVEX          = "vex"
	FactorOverride     = "override"
)

// FactorKind says how a factor enters the formula.
type FactorKind string

// Factor kinds.
const (
	KindAdditive   FactorKind = "additive"   // wS·S, wE·E, wK·K
	KindMultiplier FactorKind = "multiplier" // R, X, V
	KindOverride   FactorKind = "override"   // changes the tier, not the score
)

// Factor explains one term of the score.
type Factor struct {
	Name string     `json:"name"`
	Kind FactorKind `json:"kind"`
	// Raw is the input value as observed ("9.8", "0.94401", "true", "called", "not_affected").
	Raw string `json:"raw"`
	// Normalized is the value used in the formula: S, E, K in [0,1], or the multiplier.
	Normalized float64 `json:"normalized"`
	// Weight is the additive weight (wS, wE, wK) or, for multipliers, the multiplier applied.
	Weight float64 `json:"weight"`
	// Contribution is the factor's effect in score points: for additive factors its share of
	// 100·min(1, Σ); for multipliers the (≤ 0) change caused when applied in the order
	// reachability, exposure, VEX. Contributions sum to Score up to rounding (0.01 each).
	Contribution float64 `json:"contribution"`
	// Source says where the value came from (CVSS version, EPSS model and date, VEX author…).
	Source string `json:"source"`
	// Note adds audit detail: estimates, missing data, VEX justification, conflicts.
	Note string `json:"note,omitempty"`
}

// Flag marks a notable condition of a result, for filtering and UI badges.
type Flag string

// Flags.
const (
	FlagCVSSEstimated   Flag = "cvss-estimated"   // S came from the severity fallback
	FlagEPSSUnknown     Flag = "epss-unknown"     // no (valid) EPSS score; E = 0
	FlagKEVUnchecked    Flag = "kev-unchecked"    // no KEV catalogue was consulted
	FlagExposureUnknown Flag = "exposure-unknown" // deployment context not stated
	FlagVEXSuppressed   Flag = "vex-suppressed"   // V = 0 from a not_affected/fixed statement
	FlagVEXIgnored      Flag = "vex-ignored"      // a statement was supplied but not applied
	FlagVEXConflict     Flag = "vex-conflict"     // VEX suppression contradicts reachability=called
	FlagKEVOverride     Flag = "kev-override"     // KEV + called + internet ⇒ P1
)

// Scorer names recorded in Result.Scorer, so stored results say which model produced them.
const (
	ScorerRisk         = "aegisflow-risk/v1"
	ScorerCVSSBaseline = "cvss-baseline/v1"
)

// Result is the explained score of one finding.
type Result struct {
	FindingID string `json:"findingId,omitempty"`
	VulnID    string `json:"vulnId,omitempty"`
	Scorer    string `json:"scorer"`
	// Score is in [0, 100], rounded to 2 decimal places.
	Score   float64  `json:"score"`
	Tier    Tier     `json:"tier"`
	Action  Action   `json:"action"`
	Flags   []Flag   `json:"flags,omitempty"`
	Factors []Factor `json:"factors"`
	// Reason is a one-line human explanation.
	Reason string `json:"reason"`
}

// HasFlag reports whether the result carries f.
func (r Result) HasFlag(f Flag) bool {
	return slices.Contains(r.Flags, f)
}

// Factor returns the named factor, if present.
func (r Result) Factor(name string) (Factor, bool) {
	for _, f := range r.Factors {
		if f.Name == name {
			return f, true
		}
	}
	return Factor{}, false
}

// Scorer scores inputs; Engine and Baseline implement it.
type Scorer interface {
	Score(in Input) Result
}

// Engine is the ADR-012 risk scorer. It is immutable and safe for concurrent use.
type Engine struct {
	cfg Config
}

var _ Scorer = (*Engine)(nil)

// NewEngine validates cfg and returns an engine.
func NewEngine(cfg Config) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg}, nil
}

// Config returns the engine's configuration (record it next to experiment results).
func (e *Engine) Config() Config { return e.cfg }

// Score computes the explained risk of one finding. It never fails: missing or invalid data
// falls back to documented defaults and is flagged.
func (e *Engine) Score(in Input) Result {
	if e.cfg == (Config{}) {
		// A zero Engine (not built by NewEngine) would put everything in P1 with weight 0;
		// use the ADR-012 defaults instead.
		e = &Engine{cfg: DefaultConfig()}
	}
	c := e.cfg
	res := Result{FindingID: in.FindingID, VulnID: in.VulnID, Scorer: ScorerRisk}

	cv := selectCVSS(in, c.SeverityFallback)
	if cv.estimated {
		res.Flags = append(res.Flags, FlagCVSSEstimated)
	}
	ep := epssTerm(in.Intel)
	if !ep.known {
		res.Flags = append(res.Flags, FlagEPSSUnknown)
	}
	kev := kevTerm(in.Intel)
	if !in.Intel.KEVChecked {
		res.Flags = append(res.Flags, FlagKEVUnchecked)
	}

	s, ev, k := cv.score/10, ep.value, kev.Normalized
	base := c.Weights.CVSS*s + c.Weights.EPSS*ev + c.Weights.KEV*k
	capped := math.Min(1, base)
	share := 100.0 // points per unit of the additive sum, scaled down when the cap binds
	if base > 1 {
		share = 100 / base
	}

	cvssF := cv.factor(c.Weights.CVSS)
	cvssF.Contribution = round2(share * c.Weights.CVSS * s)
	epssF := ep.factor(c.Weights.EPSS)
	epssF.Contribution = round2(share * c.Weights.EPSS * ev)
	kev.Weight = c.Weights.KEV
	kev.Contribution = round2(share * c.Weights.KEV * k)

	running := 100 * capped
	reachF, reach := e.reachabilityFactor(in.Reachability)
	reachF.Contribution = round2(running * (reachF.Normalized - 1))
	running *= reachF.Normalized

	expF, exposure := e.exposureFactor(in.Exposure)
	if exposure == ExposureUnknown {
		res.Flags = append(res.Flags, FlagExposureUnknown)
	}
	expF.Contribution = round2(running * (expF.Normalized - 1))
	running *= expF.Normalized

	vexF, vexFlags := vexFactor(in, reach)
	res.Flags = append(res.Flags, vexFlags...)
	vexF.Contribution = round2(running * (vexF.Normalized - 1))
	running *= vexF.Normalized

	res.Score = round2(math.Max(0, math.Min(100, running)))
	res.Tier = e.tier(res.Score)
	res.Factors = []Factor{cvssF, epssF, kev, reachF, expF, vexF}

	overrideMatched := c.KEVOverride && in.Intel.KEV && reach == evidence.ReachabilityCalled && exposure == ExposureInternet
	suppressed := vexF.Normalized == 0
	raised := false
	switch {
	case overrideMatched && suppressed:
		res.Factors[5].Note = joinNotes(res.Factors[5].Note, "KEV override (KEV + called + internet) not applied: suppressed by VEX")
	case overrideMatched:
		of := Factor{Name: FactorOverride, Kind: KindOverride, Raw: "kev+called+internet", Normalized: 1, Source: "ADR-012"}
		if res.Tier == TierP1 {
			of.Note = "tier already P1 by score"
		} else {
			of.Note = fmt.Sprintf("tier raised from %s to P1", res.Tier)
			raised = true
		}
		res.Tier = TierP1
		res.Flags = append(res.Flags, FlagKEVOverride)
		res.Factors = append(res.Factors, of)
	}
	res.Action = res.Tier.Action()
	res.Reason = reason(res, explanation{cv: cv, ep: ep, intel: in.Intel, reach: reach, exposure: exposure, vex: in.VEX, raised: raised})
	return res
}

func (e *Engine) tier(score float64) Tier {
	switch {
	case score >= e.cfg.Thresholds.P1:
		return TierP1
	case score >= e.cfg.Thresholds.P2:
		return TierP2
	default:
		return TierP3
	}
}

// cvssChoice is the S term: the selected CVSS rating or the severity fallback.
type cvssChoice struct {
	score     float64 // 0..10
	version   string  // "4.0", "3.1", "3.0", "2.0"; "" when estimated
	vector    string
	estimated bool
	severity  evidence.Severity
	sameTier  int // ratings of the selected version family
	ignored   int // ratings skipped as invalid or of unknown version
}

// cvssVersionRank orders CVSS versions; the tier (rank/10) selects the family: v4 > v3.x > v2.
func cvssVersionRank(v string) (rank int, label string) {
	v = strings.ToUpper(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "CVSS:")
	v = strings.TrimPrefix(v, "V")
	switch v {
	case "4.0", "4":
		return 40, "4.0"
	case "3.1":
		return 31, "3.1"
	case "3.0", "3":
		return 30, "3.0"
	case "2.0", "2":
		return 20, "2.0"
	}
	return 0, ""
}

// selectCVSS picks S: the newest CVSS family present (v4.0, then v3.1/v3.0, then v2.0), the
// highest base score within it (conservative when sources disagree), else the fallback for
// the qualitative severity.
func selectCVSS(in Input, fb SeverityFallback) cvssChoice {
	var best cvssChoice
	bestRank := 0
	for _, r := range in.CVSS {
		rank, label := cvssVersionRank(r.Version)
		if rank == 0 || math.IsNaN(r.BaseScore) || r.BaseScore < 0 || r.BaseScore > 10 {
			best.ignored++
			continue
		}
		switch {
		case bestRank == 0 || rank/10 > bestRank/10:
			best = cvssChoice{score: r.BaseScore, version: label, vector: r.Vector, sameTier: 1, ignored: best.ignored}
			bestRank = rank
		case rank/10 == bestRank/10:
			best.sameTier++
			if r.BaseScore > best.score || (r.BaseScore == best.score && rank > bestRank) {
				best.score, best.version, best.vector, bestRank = r.BaseScore, label, r.Vector, rank
			}
		}
	}
	if bestRank > 0 {
		return best
	}
	sev := in.Severity
	if sev.Rank() == 0 && sev != evidence.SeverityUnknown {
		sev = evidence.ParseSeverity(string(sev))
	}
	return cvssChoice{score: fb.forSeverity(sev), estimated: true, severity: sev, ignored: best.ignored}
}

func (c cvssChoice) factor(weight float64) Factor {
	// Normalized is rounded for display only (9.8/10 is 0.9800000000000001 in float64).
	f := Factor{Name: FactorCVSS, Kind: KindAdditive, Raw: strconv.FormatFloat(c.score, 'f', 1, 64), Normalized: math.Round(c.score*1e5) / 1e6, Weight: weight}
	var notes []string
	if c.estimated {
		f.Source = fmt.Sprintf("severity fallback (%s)", severityName(c.severity))
		notes = append(notes, "estimated: no usable CVSS rating")
	} else {
		f.Source = "CVSS v" + c.version
		if c.vector != "" {
			notes = append(notes, clean(c.vector, 160))
		}
		if c.sameTier > 1 {
			notes = append(notes, fmt.Sprintf("highest of %d v%s ratings", c.sameTier, c.version[:1]))
		}
	}
	if c.ignored > 0 {
		notes = append(notes, fmt.Sprintf("%d invalid or unversioned rating(s) ignored", c.ignored))
	}
	f.Note = strings.Join(notes, "; ")
	return f
}

func severityName(s evidence.Severity) string {
	if s == "" {
		return string(evidence.SeverityUnknown)
	}
	return string(s)
}

// epssChoice is the E term.
type epssChoice struct {
	known       bool
	invalid     bool
	value, pct  float64
	pctKnown    bool
	model, date string
}

func validProb(v float64) bool { return !math.IsNaN(v) && v >= 0 && v <= 1 }

func epssTerm(in intel.Intel) epssChoice {
	if !in.EPSSKnown {
		return epssChoice{}
	}
	if !validProb(in.EPSS) {
		return epssChoice{invalid: true}
	}
	c := epssChoice{known: true, value: in.EPSS, model: in.ModelVersion}
	if validProb(in.Percentile) {
		c.pct, c.pctKnown = in.Percentile, true
	}
	if !in.ScoreDate.IsZero() {
		c.date = in.ScoreDate.UTC().Format("2006-01-02")
	}
	return c
}

func (c epssChoice) factor(weight float64) Factor {
	f := Factor{Name: FactorEPSS, Kind: KindAdditive, Weight: weight, Source: "EPSS"}
	if !c.known {
		f.Raw = "unknown"
		f.Note = "no EPSS score: treated as 0"
		if c.invalid {
			f.Note = "invalid EPSS value ignored: treated as 0"
		}
		return f
	}
	f.Raw = strconv.FormatFloat(c.value, 'f', -1, 64)
	f.Normalized = c.value
	var meta []string
	if c.model != "" {
		meta = append(meta, "model "+clean(c.model, 32))
	}
	if c.date != "" {
		meta = append(meta, c.date)
	}
	if len(meta) > 0 {
		f.Source += " (" + strings.Join(meta, ", ") + ")"
	}
	if c.pctKnown {
		f.Note = "percentile " + strconv.FormatFloat(c.pct, 'f', -1, 64)
	}
	return f
}

func kevTerm(in intel.Intel) Factor {
	f := Factor{Name: FactorKEV, Kind: KindAdditive, Raw: strconv.FormatBool(in.KEV), Source: "CISA KEV"}
	switch {
	case in.KEV:
		f.Normalized = 1
		notes := []string{"exploited in the wild"}
		if !in.KEVDateAdded.IsZero() {
			notes = append(notes, "added "+in.KEVDateAdded.UTC().Format("2006-01-02"))
		}
		if !in.KEVDueDate.IsZero() {
			notes = append(notes, "federal due date "+in.KEVDueDate.UTC().Format("2006-01-02"))
		}
		if in.KEVRansomware {
			notes = append(notes, "known ransomware campaign use")
		}
		f.Note = strings.Join(notes, "; ")
	case !in.KEVChecked:
		f.Note = "no KEV catalogue consulted: treated as not exploited"
	default:
		f.Note = "not listed"
	}
	return f
}

func (e *Engine) reachabilityFactor(r evidence.Reachability) (Factor, evidence.Reachability) {
	f := Factor{Name: FactorReachability, Kind: KindMultiplier, Source: "reachability analysis"}
	level := evidence.Reachability(strings.ToLower(strings.TrimSpace(string(r))))
	switch level {
	case evidence.ReachabilityCalled:
		f.Normalized = e.cfg.Reachability.Called
		f.Note = "a vulnerable symbol is in the call graph"
	case evidence.ReachabilityImported:
		f.Normalized = e.cfg.Reachability.Imported
		f.Note = "vulnerable package present but not called"
	case evidence.ReachabilityUnknown, "":
		level = evidence.ReachabilityUnknown
		f.Normalized = e.cfg.Reachability.Unknown
		f.Note = "no reachability analysis"
	default:
		f.Normalized = e.cfg.Reachability.Unknown
		f.Note = fmt.Sprintf("unrecognised value %q treated as unknown", clean(string(r), 32))
		level = evidence.ReachabilityUnknown
	}
	f.Raw = string(level)
	f.Weight = f.Normalized
	return f, level
}

func (e *Engine) exposureFactor(x Exposure) (Factor, Exposure) {
	f := Factor{Name: FactorExposure, Kind: KindMultiplier, Source: "deployment context"}
	level, err := ParseExposure(string(x))
	if err != nil {
		f.Note = fmt.Sprintf("unrecognised value %q treated as unknown", clean(string(x), 32))
		level = ExposureUnknown
	}
	switch level {
	case ExposureInternet:
		f.Normalized = e.cfg.Exposure.Internet
	case ExposureInternal:
		f.Normalized = e.cfg.Exposure.Internal
	case ExposureBuild:
		f.Normalized = e.cfg.Exposure.Build
	default:
		f.Normalized = e.cfg.Exposure.Unknown
		f.Note = joinNotes(f.Note, fmt.Sprintf("exposure not stated: multiplier %v applied (conservative)", e.cfg.Exposure.Unknown))
	}
	f.Raw = string(level)
	f.Weight = f.Normalized
	return f, level
}

// vexFactor applies an OpenVEX statement: a well-formed not_affected (with a justification
// or impact statement, as OpenVEX requires) or fixed statement naming this vulnerability
// sets V = 0; anything else leaves V = 1 and says why.
func vexFactor(in Input, reach evidence.Reachability) (Factor, []Flag) {
	f := Factor{Name: FactorVEX, Kind: KindMultiplier, Normalized: 1, Weight: 1, Raw: "none", Source: "VEX"}
	st := in.VEX
	if st == nil {
		f.Note = "no VEX statement"
		return f, nil
	}
	f.Raw = clean(string(st.Status), 32)
	f.Source = vexSource(st)
	ignore := func(why string) (Factor, []Flag) {
		f.Note = "ignored: " + why
		return f, []Flag{FlagVEXIgnored}
	}
	if !in.matchesVuln(st.VulnID) {
		return ignore(fmt.Sprintf("statement is for %q, not this vulnerability", clean(st.VulnID, 64)))
	}
	switch st.Status {
	case evidence.VEXNotAffected:
		if strings.TrimSpace(st.Justification) == "" && strings.TrimSpace(st.ImpactStatement) == "" {
			return ignore("not_affected without justification or impact statement (required by OpenVEX)")
		}
	case evidence.VEXFixed:
	case evidence.VEXAffected, evidence.VEXUnderInvestigation:
		f.Note = "status does not suppress the finding"
		return f, nil
	default:
		return ignore("unknown status")
	}
	f.Normalized, f.Weight = 0, 0
	var audit []string
	if j := strings.TrimSpace(st.Justification); j != "" {
		audit = append(audit, "justification "+clean(j, 64))
	}
	if is := strings.TrimSpace(st.ImpactStatement); is != "" {
		audit = append(audit, "impact: "+clean(is, 200))
	}
	f.Note = "suppressed by VEX " + string(st.Status)
	if len(audit) > 0 {
		f.Note += " (" + strings.Join(audit, "; ") + ")"
	}
	flags := []Flag{FlagVEXSuppressed}
	if reach == evidence.ReachabilityCalled {
		f.Note += "; conflicts with reachability=called, review the statement"
		flags = append(flags, FlagVEXConflict)
	}
	return f, flags
}

func vexSource(st *evidence.VEXStatement) string {
	src := "VEX"
	if a := strings.TrimSpace(st.Author); a != "" {
		src += " by " + clean(a, 64)
	}
	if !st.Timestamp.IsZero() {
		src += " at " + st.Timestamp.UTC().Format("2006-01-02T15:04:05Z")
	}
	return src
}

// round2 rounds to 2 decimal places (half away from zero) and normalizes -0 to 0.
func round2(v float64) float64 {
	r := math.Round(v*100) / 100
	if r == 0 {
		return 0
	}
	return r
}

// clean makes untrusted text safe for one-line explanations: control characters become
// spaces, runs of spaces collapse, and the result is truncated to max runes.
func clean(s string, maxRunes int) string {
	var b strings.Builder
	n, space := 0, false
	for _, r := range strings.ToValidUTF8(s, "�") {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			r = ' '
		}
		if r == ' ' {
			if space || n == 0 {
				continue
			}
			space = true
		} else {
			space = false
		}
		if n == maxRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimRight(b.String(), " ")
}

func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
