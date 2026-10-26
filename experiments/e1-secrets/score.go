package main

import (
	"cmp"
	"slices"
	"strconv"
)

// Breakdown is a hit rate over a group of items (recall for secrets, flag rate for decoys).
type Breakdown struct {
	Key   string  `json:"key"`
	Total int     `json:"total"`
	Hits  int     `json:"hits"`
	Rate  float64 `json:"rate"`
}

// RuleCount counts the findings of one gitleaks rule on secrets (TP) and elsewhere (FP).
type RuleCount struct {
	RuleID        string `json:"rule_id"`
	OnSecrets     int    `json:"on_secrets"`
	FalsePositive int    `json:"false_positive"`
}

// Alert is one distinct false-positive location (commit + file + start line).
type Alert struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	Commit    string `json:"commit,omitempty"`
	RuleID    string `json:"rule_id"`
	DecoyID   string `json:"decoy_id,omitempty"`
	DecoyKind string `json:"decoy_kind,omitempty"`
}

// ItemResult is the outcome for one ground-truth item: detected (secret) or flagged (decoy).
type ItemResult struct {
	ID    string   `json:"id"`
	Hit   bool     `json:"hit"`
	Rules []string `json:"rules,omitempty"`
}

// ModeResult holds the metrics of one scan mode.
//
// Definitions: a secret is detected when at least one finding has the same file, an overlapping
// line range and (history mode) the commit that introduced it. Every other finding is a false
// alarm; false alarms are de-duplicated by (commit, file, start line). Precision = TP / (TP + FP)
// with TP = detected secrets and FP = distinct false-alarm locations; recall = TP / secrets.
type ModeResult struct {
	Mode           string       `json:"mode"`
	Args           []string     `json:"args"`
	RuntimeMS      float64      `json:"runtime_ms"`
	Findings       int          `json:"findings"`
	Secrets        int          `json:"secrets"`
	TruePositives  int          `json:"true_positives"`
	FalseNegatives int          `json:"false_negatives"`
	FalsePositives int          `json:"false_positives"`
	Decoys         int          `json:"decoys"`
	DecoysFlagged  int          `json:"decoys_flagged"`
	Precision      float64      `json:"precision"`
	Recall         float64      `json:"recall"`
	F1             float64      `json:"f1"`
	PerType        []Breakdown  `json:"per_type_recall"`
	PerVariant     []Breakdown  `json:"per_variant_recall"`
	PerDecoyKind   []Breakdown  `json:"per_decoy_kind_flag_rate"`
	Rules          []RuleCount  `json:"rules"`
	FalseAlarms    []Alert      `json:"false_alarms"`
	Items          []ItemResult `json:"items"`
	itemHits       map[string]bool
}

func overlaps(f Finding, it *Item) bool {
	return f.StartLine <= it.EndLine && f.EndLine >= it.StartLine
}

// score matches findings to the ground truth. In "git" mode a finding must also carry the commit
// that introduced the item; in "dir" mode only items still present in the working tree match.
func score(run ScanRun, items []*Item) ModeResult {
	history := run.Mode == "git"
	byFile := map[string][]*Item{}
	for _, it := range items {
		byFile[it.File] = append(byFile[it.File], it)
	}

	rules := map[string]*RuleCount{}
	hitRules := map[string][]string{}
	alerts := map[string]Alert{}
	for _, f := range run.Findings {
		var match *Item
		for _, it := range byFile[f.File] {
			if !overlaps(f, it) || (history && f.Commit != it.Commit) || (!history && !it.InFinalTree) {
				continue
			}
			match = it
			break
		}
		rc := rules[f.RuleID]
		if rc == nil {
			rc = &RuleCount{RuleID: f.RuleID}
			rules[f.RuleID] = rc
		}
		if match != nil && !slices.Contains(hitRules[match.ID], f.RuleID) {
			hitRules[match.ID] = append(hitRules[match.ID], f.RuleID)
		}
		if match != nil && match.Kind == kindSecret {
			rc.OnSecrets++
			continue
		}
		rc.FalsePositive++
		key := f.Commit + "\x00" + f.File + "\x00" + strconv.Itoa(f.StartLine)
		if _, seen := alerts[key]; seen {
			continue
		}
		a := Alert{File: f.File, StartLine: f.StartLine, Commit: f.Commit, RuleID: f.RuleID}
		if match != nil {
			a.DecoyID, a.DecoyKind = match.ID, match.Type
		}
		alerts[key] = a
	}

	res := ModeResult{
		Mode:      run.Mode,
		Args:      run.Args,
		RuntimeMS: float64(run.Runtime.Microseconds()) / 1000,
		Findings:  len(run.Findings),
		itemHits:  map[string]bool{},
	}
	for _, it := range items {
		rs := hitRules[it.ID]
		slices.Sort(rs)
		hit := len(rs) > 0
		res.itemHits[it.ID] = hit
		res.Items = append(res.Items, ItemResult{ID: it.ID, Hit: hit, Rules: rs})
		if it.Kind == kindSecret {
			res.Secrets++
			if hit {
				res.TruePositives++
			}
		} else {
			res.Decoys++
			if hit {
				res.DecoysFlagged++
			}
		}
	}
	res.FalseNegatives = res.Secrets - res.TruePositives
	res.FalsePositives = len(alerts)
	res.Precision = ratio(res.TruePositives, res.TruePositives+res.FalsePositives)
	res.Recall = ratio(res.TruePositives, res.Secrets)
	if res.Precision+res.Recall > 0 {
		res.F1 = 2 * res.Precision * res.Recall / (res.Precision + res.Recall)
	}

	var typeIDs, kindIDs []string
	for _, st := range secretTypes() {
		typeIDs = append(typeIDs, st.ID)
	}
	for _, dk := range decoyKinds() {
		kindIDs = append(kindIDs, dk.ID)
	}
	res.PerType = breakdown(items, res.itemHits, kindSecret, typeIDs, func(it *Item) string { return it.Type })
	res.PerVariant = breakdown(items, res.itemHits, kindSecret, variants, func(it *Item) string { return it.Variant })
	res.PerDecoyKind = breakdown(items, res.itemHits, kindDecoy, kindIDs, func(it *Item) string { return it.Type })

	for _, rc := range rules {
		res.Rules = append(res.Rules, *rc)
	}
	slices.SortFunc(res.Rules, func(a, b RuleCount) int { return cmp.Compare(a.RuleID, b.RuleID) })
	for _, a := range alerts {
		res.FalseAlarms = append(res.FalseAlarms, a)
	}
	slices.SortFunc(res.FalseAlarms, func(a, b Alert) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.StartLine, b.StartLine), cmp.Compare(a.Commit, b.Commit))
	})
	return res
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func breakdown(items []*Item, hits map[string]bool, kind string, keys []string, keyOf func(*Item) string) []Breakdown {
	out := make([]Breakdown, len(keys))
	index := map[string]int{}
	for i, k := range keys {
		out[i].Key = k
		index[k] = i
	}
	for _, it := range items {
		i, ok := index[keyOf(it)]
		if it.Kind != kind || !ok {
			continue
		}
		out[i].Total++
		if hits[it.ID] {
			out[i].Hits++
		}
	}
	for i := range out {
		out[i].Rate = ratio(out[i].Hits, out[i].Total)
	}
	return out
}
