// Command e4-overhead runs AegisFlow experiment E4: the CI overhead of the full secure pipeline
// compared with the baseline build-and-test workflow.
//
// It reads workflow runs and jobs from the GitHub REST API (read-only), selects the newest N
// head SHAs of the baseline workflow (ci.yml), adds every other full-pipeline workflow run on the
// same SHA, and writes per-job and per-pipeline wall-clock and billed-minute statistics (median,
// p90, mean) as CSV and Markdown.
//
// The token is read from GITHUB_TOKEN (a fine-grained token with "Actions: read" is enough) and
// is never printed, logged or written to an output file.
//
// Usage:
//
//	GITHUB_TOKEN=... go run ./experiments/e4-overhead -repo OWNER/NAME [-runs 20] [-event pull_request]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// defaultWorkflows is the Phase 1 full pipeline (ROADMAP Phase 1a/1b workflow files).
const defaultWorkflows = "ci.yml,code-security.yml,supply-chain.yml,github-security.yml"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

type options struct {
	repo    string
	api     string
	outDir  string
	timeout time.Duration
	q       query
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("e4-overhead", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.repo, "repo", "", "repository OWNER/NAME (required)")
	fs.StringVar(&o.api, "api", "https://api.github.com", "GitHub REST API base URL")
	fs.StringVar(&o.q.baseline, "baseline", "ci.yml", "baseline workflow file (build + test)")
	workflows := fs.String("workflows", defaultWorkflows, "comma-separated workflow files of the full pipeline (baseline is always included)")
	fs.IntVar(&o.q.runs, "runs", 20, "number of distinct head SHAs to sample")
	fs.StringVar(&o.q.event, "event", "", "only runs triggered by this event, e.g. pull_request or push (empty: any)")
	fs.StringVar(&o.q.branch, "branch", "", "only runs on this branch (empty: any)")
	fs.StringVar(&o.q.conclusion, "conclusion", "success", "conclusion required for baseline runs (empty: any completed run)")
	outRoot := fs.String("out-root", filepath.Join("experiments", "results", "e4"), "parent directory for run results")
	fs.StringVar(&o.outDir, "out", "", "exact results directory (default: <out-root>/<UTC time>)")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Minute, "overall time limit")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	if !repoPattern.MatchString(o.repo) {
		return o, fmt.Errorf("-repo must be OWNER/NAME, got %q", o.repo)
	}
	if o.q.runs < 1 || o.q.runs > 500 {
		return o, errors.New("-runs must be in 1..500")
	}
	o.q.workflows = []string{o.q.baseline}
	for wf := range strings.SplitSeq(*workflows, ",") {
		if wf = strings.TrimSpace(wf); wf != "" && !slices.Contains(o.q.workflows, wf) {
			o.q.workflows = append(o.q.workflows, wf)
		}
	}
	for _, wf := range o.q.workflows {
		if !workflowPattern.MatchString(wf) {
			return o, fmt.Errorf("invalid workflow %q (want a file name like ci.yml or a numeric ID)", wf)
		}
	}
	if o.outDir == "" {
		o.outDir = filepath.Join(*outRoot, time.Now().UTC().Format("20060102T150405Z"))
	}
	return o, nil
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	o, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintf(stderr, "e4-overhead: %v\n", err)
		return exitUsage
	}
	base, err := parseAPIBase(o.api)
	if err != nil {
		fmt.Fprintf(stderr, "e4-overhead: %v\n", err)
		return exitUsage
	}
	token := getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintln(stderr, "e4-overhead: GITHUB_TOKEN is not set (a token with Actions: read on the repository is required)")
		return exitUsage
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	c := newClient(base, o.repo, token, logger)
	if err := execute(ctx, c, o, stdout, logger); err != nil {
		logger.Error("e4 failed", "error", err)
		return exitError
	}
	return exitOK
}

func execute(ctx context.Context, c *client, o options, stdout io.Writer, logger *slog.Logger) error {
	pipelines, err := collect(ctx, c, o.q)
	if err != nil {
		return err
	}
	if len(pipelines) == 0 {
		return fmt.Errorf("no completed %s runs matched the filters", o.q.baseline)
	}
	if len(pipelines) < o.q.runs {
		logger.Warn("fewer head SHAs than requested", "requested", o.q.runs, "collected", len(pipelines))
	}

	jobs, err := jobsCSV(pipelines)
	if err != nil {
		return err
	}
	pipes, err := pipelinesCSV(pipelines)
	if err != nil {
		return err
	}
	md := summaryMarkdown(meta{
		repo: o.repo, api: c.base.String(), generatedAt: time.Now(), q: o.q, requests: c.requests,
		jobsSHA: sha256Hex(jobs), pipesSHA: sha256Hex(pipes),
	}, pipelines)

	if err := os.MkdirAll(o.outDir, 0o750); err != nil {
		return fmt.Errorf("create results dir: %w", err)
	}
	out, err := os.OpenRoot(o.outDir)
	if err != nil {
		return fmt.Errorf("open results dir: %w", err)
	}
	defer func() { _ = out.Close() }()
	for name, data := range map[string][]byte{"jobs.csv": jobs, "pipelines.csv": pipes, "summary.md": []byte(md)} {
		if err := out.WriteFile(name, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	fmt.Fprintf(stdout, "e4: %d head SHAs, %d API requests\nresults: %s\n", len(pipelines), c.requests, o.outDir)
	return nil
}
