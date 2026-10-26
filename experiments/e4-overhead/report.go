package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Success thresholds for E4, copied from docs/ROADMAP.md ("Measurable PFE experiments"):
// <= +6 min and <= +100 % wall-clock on the PR path; <= 20 billed minutes per PR.
const (
	thresholdOverheadSeconds = 6 * 60
	thresholdOverheadPercent = 100
	thresholdBilledMinutes   = 20
)

func secs(d time.Duration) string { return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) }

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func allJobs(pipelines []Pipeline) []JobSample {
	var out []JobSample
	for _, p := range pipelines {
		out = append(out, p.Baseline.Jobs...)
		for _, o := range p.Others {
			out = append(out, o.Jobs...)
		}
	}
	return out
}

func writeCSV(rows [][]string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.WriteAll(rows); err != nil {
		return nil, fmt.Errorf("write csv: %w", err)
	}
	return buf.Bytes(), nil
}

// jobsCSV is the raw dataset: one row per job of every selected run.
func jobsCSV(pipelines []Pipeline) ([]byte, error) {
	rows := [][]string{{
		"head_sha", "workflow", "run_id", "run_attempt", "event", "job_id", "job_name", "conclusion",
		"runner_labels", "started_at", "completed_at", "duration_s", "billed_minutes", "in_baseline",
	}}
	for _, j := range allJobs(pipelines) {
		rows = append(rows, []string{
			j.HeadSHA, j.Workflow, strconv.FormatInt(j.RunID, 10), strconv.Itoa(j.RunAttempt), j.Event,
			strconv.FormatInt(j.JobID, 10), j.JobName, j.Conclusion, strings.Join(j.Labels, " "),
			rfc3339(j.StartedAt), rfc3339(j.CompletedAt), secs(j.Duration), strconv.Itoa(j.BilledMin),
			strconv.FormatBool(j.Baseline),
		})
	}
	return writeCSV(rows)
}

func overheadPercent(base, full time.Duration) float64 {
	if base <= 0 {
		return math.NaN()
	}
	return 100 * (full - base).Seconds() / base.Seconds()
}

// pipelinesCSV has one row per head SHA with baseline, full-pipeline and overhead totals.
func pipelinesCSV(pipelines []Pipeline) ([]byte, error) {
	rows := [][]string{{
		"head_sha", "baseline_run_id", "baseline_wall_s", "baseline_job_s", "baseline_billed_min",
		"full_runs", "full_wall_s", "full_job_s", "full_billed_min",
		"overhead_wall_s", "overhead_wall_pct", "overhead_billed_min", "missing_workflows",
	}}
	for _, p := range pipelines {
		b, f := p.baselineTotals(), p.fullTotals()
		rows = append(rows, []string{
			p.HeadSHA, strconv.FormatInt(p.Baseline.Run.ID, 10), secs(b.Wall), secs(b.JobTime), strconv.Itoa(b.BilledMin),
			strconv.Itoa(f.Runs), secs(f.Wall), secs(f.JobTime), strconv.Itoa(f.BilledMin),
			secs(f.Wall - b.Wall), num(overheadPercent(b.Wall, f.Wall)), strconv.Itoa(f.BilledMin - b.BilledMin),
			strings.Join(p.Missing, " "),
		})
	}
	return writeCSV(rows)
}

func num(f float64) string {
	if math.IsNaN(f) {
		return "n/a"
	}
	return strconv.FormatFloat(f, 'f', 1, 64)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// meta describes the run for the Markdown header.
type meta struct {
	repo        string
	api         string
	generatedAt time.Time
	q           query
	requests    int
	jobsSHA     string
	pipesSHA    string
}

func verdict(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// summaryMarkdown renders summary.md: sample description, totals, paired overhead, threshold
// verdicts, per-job statistics and workflow coverage.
func summaryMarkdown(m meta, pipelines []Pipeline) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	orAny := func(s string) string { return cmp.Or(s, "any") }

	w("# E4 - pipeline overhead (baseline vs full secure pipeline)\n\n")
	w("| Field | Value |\n|---|---|\n")
	w("| Repository | `%s` |\n", m.repo)
	w("| Generated | %s (API `%s`, %d requests) |\n", m.generatedAt.UTC().Format(time.RFC3339), m.api, m.requests)
	w("| Baseline | `%s` |\n", m.q.baseline)
	w("| Full pipeline | %s |\n", "`"+strings.Join(m.q.workflows, "`, `")+"`")
	w("| Filters | event=%s, branch=%s, baseline conclusion=%s |\n", orAny(m.q.event), orAny(m.q.branch), cmp.Or(m.q.conclusion, "any completed"))
	w("| Sample | %d head SHAs requested, %d collected |\n", m.q.runs, len(pipelines))
	if len(pipelines) > 0 {
		w("| SHA range (newest .. oldest) | `%s` .. `%s` |\n", short(pipelines[0].HeadSHA), short(pipelines[len(pipelines)-1].HeadSHA))
	}
	w("| jobs.csv SHA-256 | `%s` |\n", m.jobsSHA)
	w("| pipelines.csv SHA-256 | `%s` |\n\n", m.pipesSHA)

	var bWall, bJob, bBilled, fWall, fJob, fBilled, oWall, oPct, oBilled []float64
	for _, p := range pipelines {
		bt, ft := p.baselineTotals(), p.fullTotals()
		bWall, bJob, bBilled = append(bWall, bt.Wall.Seconds()), append(bJob, bt.JobTime.Seconds()), append(bBilled, float64(bt.BilledMin))
		fWall, fJob, fBilled = append(fWall, ft.Wall.Seconds()), append(fJob, ft.JobTime.Seconds()), append(fBilled, float64(ft.BilledMin))
		oWall, oBilled = append(oWall, (ft.Wall-bt.Wall).Seconds()), append(oBilled, float64(ft.BilledMin-bt.BilledMin))
		if pct := overheadPercent(bt.Wall, ft.Wall); !math.IsNaN(pct) {
			oPct = append(oPct, pct)
		}
	}

	w("## Totals per head SHA\n\n")
	w("| Metric | Baseline median | p90 | mean | Full median | p90 | mean |\n|---|---|---|---|---|---|---|\n")
	for _, r := range []struct {
		name string
		b, f []float64
	}{
		{"Wall-clock (s)", bWall, fWall},
		{"Sum of job time (s)", bJob, fJob},
		{"Billed minutes", bBilled, fBilled},
	} {
		bs, fs := summarize(r.b), summarize(r.f)
		w("| %s | %s | %s | %s | %s | %s | %s |\n", r.name, num(bs.Median), num(bs.P90), num(bs.Mean), num(fs.Median), num(fs.P90), num(fs.Mean))
	}

	w("\n## Overhead (full - baseline, paired per SHA)\n\n")
	w("| Metric | median | p90 | mean | min | max |\n|---|---|---|---|---|---|\n")
	ow, op, ob := summarize(oWall), summarize(oPct), summarize(oBilled)
	for _, r := range []struct {
		name string
		s    Summary
	}{{"Wall-clock (s)", ow}, {"Wall-clock (%)", op}, {"Billed minutes", ob}} {
		w("| %s | %s | %s | %s | %s | %s |\n", r.name, num(r.s.Median), num(r.s.P90), num(r.s.Mean), num(r.s.Min), num(r.s.Max))
	}

	fb := summarize(fBilled)
	w("\n## Thresholds (ROADMAP E4, PR path; medians)\n\n")
	w("| Criterion | Threshold | Measured | Verdict |\n|---|---|---|---|\n")
	w("| Wall-clock overhead | <= +%d s | %s s | %s |\n", thresholdOverheadSeconds, num(ow.Median), verdict(ow.Median <= thresholdOverheadSeconds))
	w("| Wall-clock overhead | <= +%d %% | %s %% | %s |\n", thresholdOverheadPercent, num(op.Median), verdict(op.Median <= thresholdOverheadPercent))
	w("| Billed minutes per PR (full pipeline) | <= %d | %s | %s |\n", thresholdBilledMinutes, num(fb.Median), verdict(fb.Median <= thresholdBilledMinutes))
	if m.q.event != "pull_request" {
		w("\nThe thresholds are defined for the PR path; this sample used event=%s.\n", orAny(m.q.event))
	}

	w("\n## Per-job durations\n\n")
	w("| Workflow | Job | n | median s | p90 s | mean s | median billed min |\n|---|---|---|---|---|---|---|\n")
	type key struct{ wf, job string }
	durations, billed := map[key][]float64{}, map[key][]float64{}
	var keys []key
	for _, j := range allJobs(pipelines) {
		k := key{j.Workflow, j.JobName}
		if _, ok := durations[k]; !ok {
			keys = append(keys, k)
		}
		durations[k] = append(durations[k], j.Duration.Seconds())
		billed[k] = append(billed[k], float64(j.BilledMin))
	}
	slices.SortFunc(keys, func(a, b key) int { return cmp.Or(cmp.Compare(a.wf, b.wf), cmp.Compare(a.job, b.job)) })
	for _, k := range keys {
		ds, bs := summarize(durations[k]), summarize(billed[k])
		w("| `%s` | %s | %d | %s | %s | %s | %s |\n", k.wf, k.job, ds.N, num(ds.Median), num(ds.P90), num(ds.Mean), num(bs.Median))
	}

	w("\n## Workflow coverage\n\n| Workflow | SHAs with a run | SHAs missing |\n|---|---|---|\n")
	for _, wf := range m.q.workflows {
		with := 0
		for _, p := range pipelines {
			if wf == m.q.baseline || slices.ContainsFunc(p.Others, func(r RunSample) bool { return r.Workflow == wf }) {
				with++
			}
		}
		w("| `%s` | %d | %d |\n", wf, with, len(pipelines)-with)
	}

	w("\n## Notes\n\n")
	for _, n := range []string{
		"Wall-clock = earliest run start (run_started_at) to the last job completion across the runs of one head SHA; the workflows run in parallel, so this is what a developer waits for.",
		"Billed minutes = sum over jobs of the duration rounded up to a whole minute, times the runner multiplier (Linux 1, Windows 2, macOS 10, self-hosted 0). Public repositories are not billed for standard runners; the figure still measures quota use.",
		"Baseline runs are the newest completed runs of the baseline workflow (one per head SHA); other workflows contribute their newest completed, non-cancelled run on the same SHA. Missing workflows (path filters, not yet merged) count as zero.",
		"Statistics: p90 uses linear interpolation between closest ranks (NumPy default). Queue time before a job starts is excluded from job time but included in wall-clock.",
	} {
		w("- %s\n", n)
	}
	return b.String()
}

func short(sha string) string { return sha[:min(12, len(sha))] }
