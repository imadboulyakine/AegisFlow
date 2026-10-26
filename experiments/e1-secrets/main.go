// Command e1-secrets runs AegisFlow experiment E1, the secret-detection benchmark.
//
// From a fixed seed it generates a synthetic git repository with seeded credentials (10 types x
// 5 variants: plain, config file, base64, split across lines, history only) and look-alike
// decoys (10 kinds), runs a pinned gitleaks binary over the full history ("git" mode) and the
// working tree ("dir" mode), matches findings to the ground truth by commit + file + line and
// writes precision, recall, per-type recall, false positives and runtime as JSON and Markdown.
//
// No credential-shaped literal exists in this source: values are built at runtime from public
// format prefixes plus seeded pseudo-random characters, so scanning this repository stays
// clean. The fixture repository lives in a temporary directory and is deleted unless -keep-repo.
//
// Usage (see experiments/README.md; `make e1` installs the pinned gitleaks first):
//
//	go run ./experiments/e1-secrets -gitleaks PATH [-config .gitleaks.toml] [-seed N] [-reps N]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	seed         int64
	reps         int
	commits      int
	gitleaks     string
	wantVersion  string
	config       string
	modes        []string
	outDir       string
	keepRepo     bool
	generateOnly bool
	timeout      time.Duration
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("e1-secrets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Int64Var(&o.seed, "seed", 20261026, "PRNG seed; the same seed and toolchain give a byte-identical dataset")
	fs.IntVar(&o.reps, "reps", 1, "repetitions of the 10 types x 5 variants design (50 secrets + 50 decoys each)")
	fs.IntVar(&o.commits, "commits", 12, "feature commits the items are spread over (plus skeleton and cleanup)")
	fs.StringVar(&o.gitleaks, "gitleaks", "gitleaks", "gitleaks binary (`make e1` installs the pinned version)")
	fs.StringVar(&o.wantVersion, "gitleaks-version", "", "required gitleaks module version, e.g. v8.30.1 (empty: any gitleaks v8 build)")
	fs.StringVar(&o.config, "config", "", "gitleaks config file (empty: built-in default rules)")
	modes := fs.String("modes", "git,dir", "comma-separated scan modes: git (full history), dir (working tree)")
	outRoot := fs.String("out-root", filepath.Join("experiments", "results", "e1"), "parent directory for run results")
	fs.StringVar(&o.outDir, "out", "", "exact results directory (default: <out-root>/<UTC time>-seed<seed>)")
	fs.BoolVar(&o.keepRepo, "keep-repo", false, "keep the generated fixture repository and print its path")
	fs.BoolVar(&o.generateOnly, "generate-only", false, "generate the fixture repository and ground truth, do not scan")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Minute, "overall time limit")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	for m := range strings.SplitSeq(*modes, ",") {
		m = strings.TrimSpace(m)
		if m != "git" && m != "dir" {
			return o, fmt.Errorf("unknown mode %q (want git or dir)", m)
		}
		if !slices.Contains(o.modes, m) {
			o.modes = append(o.modes, m)
		}
	}
	if o.reps < 1 || o.reps > 100 || o.commits < 1 || o.commits > 1000 {
		return o, errors.New("-reps must be in 1..100 and -commits in 1..1000")
	}
	if o.outDir == "" {
		o.outDir = filepath.Join(*outRoot, time.Now().UTC().Format("20060102T150405Z")+"-seed"+strconv.FormatInt(o.seed, 10))
	}
	return o, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintf(stderr, "e1-secrets: %v\n", err)
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if err := execute(ctx, o, stdout, logger); err != nil {
		logger.Error("e1 failed", "error", err)
		return exitError
	}
	return exitOK
}

func execute(ctx context.Context, o options, stdout io.Writer, logger *slog.Logger) error {
	start := time.Now()
	ds, err := buildDataset(o.seed, o.reps, o.commits)
	if err != nil {
		return err
	}
	repoDir, err := os.MkdirTemp("", "aegisflow-e1-")
	if err != nil {
		return fmt.Errorf("create fixture dir: %w", err)
	}
	if o.keepRepo || o.generateOnly {
		logger.Info("fixture repository kept", "path", repoDir)
	} else {
		defer func() { _ = os.RemoveAll(repoDir) }()
	}
	if err := ds.materialize(ctx, repoDir); err != nil {
		return err
	}
	nSecrets, nDecoys := ds.counts()
	logger.Info("fixture generated", "secrets", nSecrets, "decoys", nDecoys, "commits", len(ds.Commits),
		"head", ds.HeadCommit, "manifest", ds.ManifestSHA256, "elapsed", time.Since(start).Round(time.Millisecond))

	if err := os.MkdirAll(o.outDir, 0o750); err != nil {
		return fmt.Errorf("create results dir: %w", err)
	}
	outDir, err := filepath.Abs(o.outDir)
	if err != nil {
		return fmt.Errorf("resolve results dir: %w", err)
	}
	out, err := os.OpenRoot(outDir)
	if err != nil {
		return fmt.Errorf("open results dir: %w", err)
	}
	defer func() { _ = out.Close() }()

	gt, gtSum, err := groundTruthJSON(ds)
	if err != nil {
		return err
	}
	if err := out.WriteFile("ground-truth.json", gt, 0o600); err != nil {
		return fmt.Errorf("write ground truth: %w", err)
	}
	if o.generateOnly {
		fmt.Fprintf(stdout, "fixture: %s\nground truth: %s\n", repoDir, filepath.Join(outDir, "ground-truth.json"))
		return nil
	}

	tool, err := inspectTool(o.gitleaks, o.wantVersion, o.config)
	if err != nil {
		return err
	}
	logger.Info("scanner", "module", tool.Module, "version", tool.Version, "config", tool.Config)

	res := &Results{
		Experiment:    "E1-secret-detection",
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Parameters:    Parameters{Seed: o.seed, Reps: o.reps, Commits: o.commits, Modes: o.modes},
		Dataset:       datasetInfo(ds, gtSum),
		Tool:          tool,
		Environment:   environment(ctx),
		Thresholds:    Thresholds{RecallMin: thresholdRecall, PrecisionMin: thresholdPrecision, DetectMax: thresholdDetect},
		Notes:         notes(),
	}
	for _, mode := range o.modes {
		scan, err := runGitleaks(ctx, tool, mode, repoDir, filepath.Join(outDir, "findings-"+mode+".json"))
		if err != nil {
			return err
		}
		m := score(scan, ds.Items)
		logger.Info("scan scored", "mode", mode, "recall", m.Recall, "precision", m.Precision,
			"tp", m.TruePositives, "fp", m.FalsePositives, "runtime_ms", m.RuntimeMS)
		res.Modes = append(res.Modes, m)
	}
	headline := res.Modes[0]
	res.Verdict = Verdict{
		Mode:          headline.Mode,
		RecallPass:    headline.Recall >= thresholdRecall,
		PrecisionPass: headline.Precision >= thresholdPrecision,
		TimeToDetect:  "not measured here: CI-only (see experiments/README.md)",
	}

	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("encode results: %w", err)
	}
	if err := out.WriteFile("results.json", append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write results.json: %w", err)
	}
	if err := out.WriteFile("results.md", []byte(markdown(res, ds)), 0o600); err != nil {
		return fmt.Errorf("write results.md: %w", err)
	}

	for _, m := range res.Modes {
		fmt.Fprintf(stdout, "%-4s recall=%.3f precision=%.3f f1=%.3f tp=%d fn=%d fp=%d decoys_flagged=%d/%d runtime=%.0fms\n",
			m.Mode, m.Recall, m.Precision, m.F1, m.TruePositives, m.FalseNegatives, m.FalsePositives, m.DecoysFlagged, m.Decoys, m.RuntimeMS)
	}
	fmt.Fprintf(stdout, "verdict (%s): recall %s, precision %s\nresults: %s\n", res.Verdict.Mode,
		passFail(res.Verdict.RecallPass), passFail(res.Verdict.PrecisionPass), outDir)
	return nil
}

func datasetInfo(ds *Dataset, gtSum string) DatasetInfo {
	info := DatasetInfo{
		Variants:          variants,
		Commits:           len(ds.Commits),
		ManifestSHA256:    ds.ManifestSHA256,
		GroundTruthSHA256: gtSum,
		HeadCommit:        ds.HeadCommit,
	}
	info.Secrets, info.Decoys = ds.counts()
	for _, st := range secretTypes() {
		info.SecretTypes = append(info.SecretTypes, st.ID)
	}
	for _, dk := range decoyKinds() {
		info.DecoyKinds = append(info.DecoyKinds, dk.ID)
	}
	files := map[string]bool{}
	for _, c := range ds.Commits {
		for _, w := range c.writes {
			files[w.path] = true
		}
	}
	info.Files = len(files)
	return info
}

func environment(ctx context.Context) Environment {
	gitVersion, err := runGit(ctx, "", fixtureEpoch, "--version")
	if err != nil {
		gitVersion = "unknown"
	}
	return Environment{
		GoVersion:  runtime.Version(),
		GitVersion: strings.TrimPrefix(gitVersion, "git version "),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		CPUs:       runtime.NumCPU(),
	}
}

func notes() []string {
	return []string{
		"Synthetic data only: every value is generated at runtime from a public format prefix and seeded random characters; none is a live credential.",
		"git mode scans every commit (like the nightly full-history job; a PR scan is the same over the PR's commits); dir mode scans only the final working tree, so history-only secrets are expected misses there.",
		"Matching: same file, overlapping lines and (git mode) the introducing commit. False alarms are de-duplicated by commit + file + start line.",
		"Precision = detected secrets / (detected secrets + distinct false-alarm locations); recall = detected secrets / seeded secrets.",
		"Runtime is the wall-clock time of one gitleaks process on this machine; time-to-detect in CI (commit -> failing check) is measured separately on a fixture branch.",
		"Findings files are written with --redact; the ground truth stores only SHA-256 fingerprints and 4-character previews of seeded values.",
	}
}
