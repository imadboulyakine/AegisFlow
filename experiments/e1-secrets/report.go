package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Success thresholds for E1, copied from docs/ROADMAP.md ("Measurable PFE experiments").
const (
	thresholdRecall    = 0.90
	thresholdPrecision = 0.80
	thresholdDetect    = "3m (commit -> failing check; measured in CI, not by this harness)"
)

// Results is the machine-readable output of one E1 run (results.json).
type Results struct {
	Experiment    string       `json:"experiment"`
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   string       `json:"generated_at"`
	Parameters    Parameters   `json:"parameters"`
	Dataset       DatasetInfo  `json:"dataset"`
	Tool          ToolInfo     `json:"tool"`
	Environment   Environment  `json:"environment"`
	Thresholds    Thresholds   `json:"thresholds"`
	Verdict       Verdict      `json:"verdict"`
	Modes         []ModeResult `json:"modes"`
	Notes         []string     `json:"notes"`
}

// Parameters are the inputs that, with the tool versions, fully determine a run.
type Parameters struct {
	Seed    int64    `json:"seed"`
	Reps    int      `json:"reps"`
	Commits int      `json:"feature_commits"`
	Modes   []string `json:"modes"`
}

// DatasetInfo identifies the generated fixture; equal hashes mean an identical dataset.
type DatasetInfo struct {
	Secrets           int      `json:"secrets"`
	Decoys            int      `json:"decoys"`
	SecretTypes       []string `json:"secret_types"`
	Variants          []string `json:"variants"`
	DecoyKinds        []string `json:"decoy_kinds"`
	Commits           int      `json:"commits"`
	Files             int      `json:"files"`
	ManifestSHA256    string   `json:"manifest_sha256"`
	GroundTruthSHA256 string   `json:"ground_truth_sha256"`
	HeadCommit        string   `json:"head_commit"`
}

// Environment records where the run happened.
type Environment struct {
	GoVersion  string `json:"go_version"`
	GitVersion string `json:"git_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	CPUs       int    `json:"cpus"`
}

// Thresholds are the ROADMAP success criteria.
type Thresholds struct {
	RecallMin    float64 `json:"recall_min"`
	PrecisionMin float64 `json:"precision_min"`
	DetectMax    string  `json:"time_to_detect_max"`
}

// Verdict applies the thresholds to the headline mode (full-history scan).
type Verdict struct {
	Mode          string `json:"mode"`
	RecallPass    bool   `json:"recall_pass"`
	PrecisionPass bool   `json:"precision_pass"`
	TimeToDetect  string `json:"time_to_detect"`
}

func groundTruthJSON(ds *Dataset) ([]byte, string, error) {
	items := slices.Clone(ds.Items)
	slices.SortFunc(items, func(a, b *Item) int { return strings.Compare(a.ID, b.ID) })
	raw, err := json.MarshalIndent(struct {
		Seed    int64   `json:"seed"`
		Reps    int     `json:"reps"`
		Commits []any   `json:"commits"`
		Items   []*Item `json:"items"`
	}{ds.Seed, ds.Reps, commitSummaries(ds), items}, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("encode ground truth: %w", err)
	}
	raw = append(raw, '\n')
	sum := sha256.Sum256(raw)
	return raw, "sha256:" + hexEncode(sum[:]), nil
}

func commitSummaries(ds *Dataset) []any {
	out := make([]any, 0, len(ds.Commits))
	for _, c := range ds.Commits {
		out = append(out, struct {
			Index   int    `json:"index"`
			SHA     string `json:"sha"`
			Message string `json:"message"`
			Files   int    `json:"files_written"`
		}{c.Index, c.SHA, firstLine(c.Message), len(c.writes)})
	}
	return out
}

func pct(f float64) string { return fmt.Sprintf("%.1f %%", 100*f) }

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// markdown renders results.md: headline metrics, per-type x variant recall, decoys, misses.
func markdown(r *Results, ds *Dataset) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# E1 - secret detection benchmark (gitleaks)\n\n")
	w("| Field | Value |\n|---|---|\n")
	w("| Generated | %s |\n", r.GeneratedAt)
	w("| Seed / reps / feature commits | %d / %d / %d |\n", r.Parameters.Seed, r.Parameters.Reps, r.Parameters.Commits)
	w("| Dataset | %d secrets (%d types x %d variants x %d reps), %d decoys (%d kinds), %d commits, %d files |\n",
		r.Dataset.Secrets, len(r.Dataset.SecretTypes), len(r.Dataset.Variants), r.Parameters.Reps,
		r.Dataset.Decoys, len(r.Dataset.DecoyKinds), r.Dataset.Commits, r.Dataset.Files)
	w("| Manifest SHA-256 | `%s` |\n", r.Dataset.ManifestSHA256)
	w("| Ground truth SHA-256 | `%s` |\n", r.Dataset.GroundTruthSHA256)
	w("| Fixture HEAD | `%s` |\n", r.Dataset.HeadCommit)
	w("| Tool | %s %s (`%s`), built with %s |\n", r.Tool.Module, r.Tool.Version, r.Tool.ModuleSum, r.Tool.GoVersion)
	w("| Binary SHA-256 | `%s` |\n", r.Tool.BinarySHA256)
	cfg := r.Tool.Config
	if r.Tool.ConfigSHA256 != "" {
		cfg += " (`" + r.Tool.ConfigSHA256 + "`)"
	}
	w("| Config | %s |\n", cfg)
	w("| Environment | %s, git %s, %s/%s, %d CPUs |\n\n", r.Environment.GoVersion, r.Environment.GitVersion, r.Environment.OS, r.Environment.Arch, r.Environment.CPUs)

	w("## Headline\n\n")
	w("| Mode | Recall | Precision | F1 | TP | FN | FP alerts | Decoys flagged | Findings | Runtime |\n")
	w("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, m := range r.Modes {
		w("| %s | %s | %s | %.3f | %d | %d | %d | %d/%d | %d | %.0f ms |\n", modeLabel(m.Mode), pct(m.Recall), pct(m.Precision), m.F1,
			m.TruePositives, m.FalseNegatives, m.FalsePositives, m.DecoysFlagged, m.Decoys, m.Findings, m.RuntimeMS)
	}
	w("\nThresholds (ROADMAP E1, applied to `%s` mode): recall >= %.2f **%s**, precision >= %.2f **%s**, time-to-detect < %s.\n\n",
		r.Verdict.Mode, r.Thresholds.RecallMin, passFail(r.Verdict.RecallPass), r.Thresholds.PrecisionMin,
		passFail(r.Verdict.PrecisionPass), r.Thresholds.DetectMax)

	for _, m := range r.Modes {
		w("## %s\n\n", modeLabel(m.Mode))
		w("Detected secrets per type and variant (hits/total):\n\n")
		w("| Type | %s | Recall |\n|---|%s---|\n", strings.Join(r.Dataset.Variants, " | "), strings.Repeat("---|", len(r.Dataset.Variants)))
		for _, bt := range m.PerType {
			cells := make([]string, 0, len(r.Dataset.Variants))
			for _, v := range r.Dataset.Variants {
				hits, total := 0, 0
				for _, it := range ds.Items {
					if it.Kind == kindSecret && it.Type == bt.Key && it.Variant == v {
						total++
						if m.itemHits[it.ID] {
							hits++
						}
					}
				}
				cells = append(cells, fmt.Sprintf("%d/%d", hits, total))
			}
			w("| %s | %s | %s |\n", bt.Key, strings.Join(cells, " | "), pct(bt.Rate))
		}
		w("| **all** |")
		for _, bv := range m.PerVariant {
			w(" %s |", pct(bv.Rate))
		}
		w(" **%s** |\n\n", pct(m.Recall))

		w("Decoys flagged (false positives) per kind:\n\n| Decoy kind | Flagged | Rate |\n|---|---|---|\n")
		for _, bd := range m.PerDecoyKind {
			w("| %s | %d/%d | %s |\n", bd.Key, bd.Hits, bd.Total, pct(bd.Rate))
		}
		w("\nFindings per rule:\n\n| Rule | On secrets | False positive |\n|---|---|---|\n")
		for _, rc := range m.Rules {
			w("| %s | %d | %d |\n", rc.RuleID, rc.OnSecrets, rc.FalsePositive)
		}
		if len(m.FalseAlarms) > 0 {
			w("\nFalse alarms:\n\n| File | Line | Rule | Decoy |\n|---|---|---|---|\n")
			for _, a := range m.FalseAlarms {
				decoy := "(not a decoy line)"
				if a.DecoyID != "" {
					decoy = a.DecoyID + " " + a.DecoyKind
				}
				w("| `%s` | %d | %s | %s |\n", a.File, a.StartLine, a.RuleID, decoy)
			}
		}
		var missed []string
		for _, it := range ds.Items {
			if it.Kind == kindSecret && !m.itemHits[it.ID] {
				missed = append(missed, fmt.Sprintf("| %s | %s | %s | `%s:%d` |", it.ID, it.Type, it.Variant, it.File, it.StartLine))
			}
		}
		if len(missed) > 0 {
			w("\nMissed secrets:\n\n| ID | Type | Variant | Location |\n|---|---|---|---|\n%s\n", strings.Join(missed, "\n"))
		}
		w("\n")
	}

	w("## Notes\n\n")
	for _, n := range r.Notes {
		w("- %s\n", n)
	}
	return b.String()
}

func modeLabel(mode string) string {
	switch mode {
	case "git":
		return "git (full history)"
	case "dir":
		return "dir (working tree)"
	}
	return mode
}
