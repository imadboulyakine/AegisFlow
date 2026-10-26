package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"
)

// query selects the runs that make up the sample.
type query struct {
	baseline   string   // workflow file of the baseline pipeline (build + test)
	workflows  []string // every workflow of the full pipeline, baseline included
	runs       int      // number of distinct head SHAs to sample
	event      string   // optional event filter (pull_request, push, ...)
	branch     string   // optional branch filter
	conclusion string   // optional conclusion filter for the baseline runs (default success)
}

// JobSample is one job of one selected run.
type JobSample struct {
	HeadSHA     string
	Workflow    string
	RunID       int64
	RunAttempt  int
	Event       string
	JobID       int64
	JobName     string
	Conclusion  string
	Labels      []string
	StartedAt   time.Time
	CompletedAt time.Time
	Duration    time.Duration
	BilledMin   int
	Baseline    bool
}

// RunSample is a selected workflow run with its jobs.
type RunSample struct {
	Workflow string
	Run      Run
	Jobs     []JobSample
}

// Pipeline groups the runs of one head SHA: the baseline run and every full-pipeline run.
type Pipeline struct {
	HeadSHA  string
	Baseline RunSample
	Others   []RunSample // full-pipeline runs other than the baseline
	Missing  []string    // full-pipeline workflows with no usable run for this SHA
}

// billedMinutes applies GitHub's per-job billing rule: each job's duration is rounded up to the
// next whole minute and multiplied by the runner OS multiplier (Linux 1, Windows 2, macOS 10;
// self-hosted runners are free). Larger runners have other rates and are not modelled.
func billedMinutes(d time.Duration, labels []string) int {
	if d <= 0 {
		return 0
	}
	multiplier := 1
	for _, l := range labels {
		l = strings.ToLower(l)
		switch {
		case l == "self-hosted":
			return 0
		case strings.Contains(l, "windows"):
			multiplier = 2
		case strings.Contains(l, "macos"):
			multiplier = 10
		}
	}
	return int(math.Ceil(d.Minutes())) * multiplier
}

func jobSamples(workflow string, run Run, jobs []Job, baseline bool) []JobSample {
	out := make([]JobSample, 0, len(jobs))
	for _, j := range jobs {
		var d time.Duration
		if !j.StartedAt.IsZero() && j.CompletedAt.After(j.StartedAt) {
			d = j.CompletedAt.Sub(j.StartedAt)
		}
		out = append(out, JobSample{
			HeadSHA: run.HeadSHA, Workflow: workflow, RunID: run.ID, RunAttempt: run.RunAttempt, Event: run.Event,
			JobID: j.ID, JobName: j.Name, Conclusion: j.Conclusion, Labels: j.Labels,
			StartedAt: j.StartedAt, CompletedAt: j.CompletedAt, Duration: d,
			BilledMin: billedMinutes(d, j.Labels), Baseline: baseline,
		})
	}
	return out
}

// usable reports whether a run of a non-baseline workflow counts towards the full pipeline:
// it must be completed and must not have been cancelled or skipped (partial or no work).
func usable(r Run) bool {
	return r.Status == "completed" && r.Conclusion != "cancelled" && r.Conclusion != "skipped"
}

// collect selects the newest `runs` distinct head SHAs of the baseline workflow and, for each,
// the newest usable run of every other full-pipeline workflow on the same SHA.
func collect(ctx context.Context, c *client, q query) ([]Pipeline, error) {
	bq := url.Values{}
	if q.conclusion != "" {
		bq.Set("status", q.conclusion) // the API accepts conclusions in the status filter
	} else {
		bq.Set("status", "completed")
	}
	if q.event != "" {
		bq.Set("event", q.event)
	}
	if q.branch != "" {
		bq.Set("branch", q.branch)
	}
	// Re-runs and duplicate events can repeat a SHA, so over-fetch and de-duplicate.
	baseRuns, err := c.listRuns(ctx, q.baseline, bq, 3*q.runs)
	if err != nil {
		return nil, fmt.Errorf("list %s runs: %w", q.baseline, err)
	}

	missingWorkflow := map[string]bool{}
	var pipelines []Pipeline
	seen := map[string]bool{}
	for _, br := range baseRuns {
		if len(pipelines) == q.runs {
			break
		}
		if br.Status != "completed" || seen[br.HeadSHA] {
			continue
		}
		seen[br.HeadSHA] = true
		jobs, err := c.listJobs(ctx, br.ID)
		if err != nil {
			return nil, fmt.Errorf("jobs of run %d: %w", br.ID, err)
		}
		p := Pipeline{HeadSHA: br.HeadSHA, Baseline: RunSample{q.baseline, br, jobSamples(q.baseline, br, jobs, true)}}

		for _, wf := range q.workflows {
			if wf == q.baseline {
				continue
			}
			if missingWorkflow[wf] {
				p.Missing = append(p.Missing, wf)
				continue
			}
			oq := url.Values{"head_sha": {br.HeadSHA}}
			if q.event != "" {
				oq.Set("event", q.event)
			}
			runs, err := c.listRuns(ctx, wf, oq, 20)
			if errors.Is(err, errNotFound) {
				c.logger.Warn("workflow not found; counted as missing for every SHA", "workflow", wf)
				missingWorkflow[wf] = true
				p.Missing = append(p.Missing, wf)
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("list %s runs for %s: %w", wf, br.HeadSHA, err)
			}
			idx := slices.IndexFunc(runs, usable)
			if idx < 0 {
				p.Missing = append(p.Missing, wf)
				continue
			}
			r := runs[idx]
			jobs, err := c.listJobs(ctx, r.ID)
			if err != nil {
				return nil, fmt.Errorf("jobs of run %d: %w", r.ID, err)
			}
			p.Others = append(p.Others, RunSample{wf, r, jobSamples(wf, r, jobs, false)})
		}
		pipelines = append(pipelines, p)
	}
	return pipelines, nil
}

// Totals are the aggregate measurements of a set of runs.
type Totals struct {
	Wall      time.Duration // first run start -> last job completion
	JobTime   time.Duration // sum of job durations
	BilledMin int
	Runs      int
}

func totals(runs ...RunSample) Totals {
	var t Totals
	var start, end time.Time
	for _, rs := range runs {
		t.Runs++
		s := rs.Run.RunStartedAt
		if s.IsZero() {
			s = rs.Run.CreatedAt
		}
		if start.IsZero() || s.Before(start) {
			start = s
		}
		runEnd := rs.Run.UpdatedAt
		if len(rs.Jobs) > 0 {
			runEnd = time.Time{}
		}
		for _, j := range rs.Jobs {
			t.JobTime += j.Duration
			t.BilledMin += j.BilledMin
			if j.CompletedAt.After(runEnd) {
				runEnd = j.CompletedAt
			}
		}
		if runEnd.After(end) {
			end = runEnd
		}
	}
	if end.After(start) {
		t.Wall = end.Sub(start)
	}
	return t
}

func (p Pipeline) baselineTotals() Totals { return totals(p.Baseline) }

func (p Pipeline) fullTotals() Totals { return totals(append([]RunSample{p.Baseline}, p.Others...)...) }
