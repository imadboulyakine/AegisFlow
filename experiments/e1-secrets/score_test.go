package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testItems() []*Item {
	return []*Item{
		{ID: "s001", Kind: kindSecret, Type: "github-pat-classic", Variant: variantPlain, File: "a.go", StartLine: 5, EndLine: 5, Commit: "c1", InFinalTree: true},
		{ID: "s002", Kind: kindSecret, Type: "private-key-pem", Variant: variantConfig, File: "k.key", StartLine: 1, EndLine: 20, Commit: "c1", InFinalTree: true},
		{ID: "s003", Kind: kindSecret, Type: "jwt", Variant: variantHistory, File: "h.py", StartLine: 3, EndLine: 3, Commit: "c2", InFinalTree: false},
		{ID: "s004", Kind: kindSecret, Type: "postgres-uri", Variant: variantSplit, File: "p.ts", StartLine: 2, EndLine: 4, Commit: "c2", InFinalTree: true},
		{ID: "d001", Kind: kindDecoy, Type: "placeholder", Resembles: "github-pat-classic", File: ".env.example", StartLine: 2, EndLine: 2, Commit: "c1", InFinalTree: true},
		{ID: "d002", Kind: kindDecoy, Type: "image-digest", Resembles: "generic-api-key", File: "Dockerfile", StartLine: 1, EndLine: 1, Commit: "c2", InFinalTree: true},
	}
}

func TestScoreHistoryMode(t *testing.T) {
	t.Parallel()
	run := ScanRun{Mode: "git", Runtime: 1500 * time.Microsecond, Findings: []Finding{
		{RuleID: "github-pat", File: "a.go", StartLine: 5, EndLine: 5, Commit: "c1"},
		{RuleID: "generic-api-key", File: "a.go", StartLine: 5, EndLine: 5, Commit: "c1"}, // second rule, same secret
		{RuleID: "private-key", File: "k.key", StartLine: 1, EndLine: 20, Commit: "c1"},
		{RuleID: "jwt", File: "h.py", StartLine: 3, EndLine: 3, Commit: "c2"},
		{RuleID: "jwt", File: "h.py", StartLine: 3, EndLine: 3, Commit: "c3"},                // same line, wrong commit: FP
		{RuleID: "github-pat", File: ".env.example", StartLine: 2, EndLine: 2, Commit: "c1"}, // decoy: FP
		{RuleID: "generic-api-key", File: ".env.example", StartLine: 2, EndLine: 2, Commit: "c1"},
		{RuleID: "generic-api-key", File: "main.go", StartLine: 9, EndLine: 9, Commit: "c1"}, // filler: FP
	}}
	m := score(run, testItems())
	if m.TruePositives != 3 || m.FalseNegatives != 1 || m.FalsePositives != 3 || m.DecoysFlagged != 1 || m.Findings != 8 {
		t.Fatalf("tp=%d fn=%d fp=%d decoys=%d findings=%d", m.TruePositives, m.FalseNegatives, m.FalsePositives, m.DecoysFlagged, m.Findings)
	}
	if m.Recall != 0.75 || m.Precision != 0.5 || m.RuntimeMS != 1.5 {
		t.Errorf("recall=%v precision=%v runtime=%v", m.Recall, m.Precision, m.RuntimeMS)
	}
	if f1 := 2 * 0.5 * 0.75 / 1.25; m.F1 != f1 {
		t.Errorf("f1 = %v, want %v", m.F1, f1)
	}
	if m.Items[0].ID != "s001" || strings.Join(m.Items[0].Rules, ",") != "generic-api-key,github-pat" {
		t.Errorf("item s001 = %+v", m.Items[0])
	}
	if len(m.FalseAlarms) != 3 || m.FalseAlarms[0].File != ".env.example" || m.FalseAlarms[0].DecoyKind != "placeholder" {
		t.Errorf("false alarms = %+v", m.FalseAlarms)
	}
	for _, b := range m.PerVariant {
		if b.Key == variantSplit && (b.Total != 1 || b.Hits != 0) {
			t.Errorf("split breakdown = %+v", b)
		}
	}
	for _, rc := range m.Rules {
		if rc.RuleID == "generic-api-key" && (rc.OnSecrets != 1 || rc.FalsePositive != 2) {
			t.Errorf("generic-api-key counts = %+v", rc)
		}
	}
}

func TestScoreWorkingTreeMode(t *testing.T) {
	t.Parallel()
	run := ScanRun{Mode: "dir", Findings: []Finding{
		{RuleID: "github-pat", File: "a.go", StartLine: 5, EndLine: 5},
		{RuleID: "jwt", File: "h.py", StartLine: 3, EndLine: 3}, // history-only secret is gone from the tree
		{RuleID: "x", File: "p.ts", StartLine: 4, EndLine: 4},   // overlaps the last line of a split secret
	}}
	m := score(run, testItems())
	if m.TruePositives != 2 || m.FalsePositives != 1 || m.Recall != 0.5 {
		t.Errorf("tp=%d fp=%d recall=%v", m.TruePositives, m.FalsePositives, m.Recall)
	}
}

func TestScoreNoFindings(t *testing.T) {
	t.Parallel()
	m := score(ScanRun{Mode: "git"}, testItems())
	if m.Precision != 0 || m.Recall != 0 || m.F1 != 0 || m.FalseNegatives != 4 {
		t.Errorf("empty scan = %+v", m)
	}
}

func TestParseReport(t *testing.T) {
	t.Parallel()
	repo := filepath.Join(string(filepath.Separator), "tmp", "fixture")
	raw := []byte(`[{"RuleID":"r","File":"` + filepath.ToSlash(filepath.Join(repo, "config", "a.yaml")) + `","StartLine":4,"EndLine":0,"Commit":"","Secret":"REDACTED"},
		{"RuleID":"r","File":"./b.go","StartLine":2,"EndLine":3,"Commit":"abc"}]`)
	got, err := parseReport(raw, repo)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].File != "config/a.yaml" || got[0].EndLine != 4 || got[1].File != "b.go" {
		t.Errorf("parsed = %+v", got)
	}
	if _, err := parseReport([]byte("not json"), repo); err == nil {
		t.Error("invalid report accepted")
	}
}

func TestPortableArgs(t *testing.T) {
	t.Parallel()
	got := portableArgs([]string{"git", "--report-path", "/out/findings-git.json", "--config", "/src/.gitleaks.toml", "/tmp/repo"}, "/tmp/repo", "/out/findings-git.json")
	if strings.Join(got, " ") != "git --report-path findings-git.json --config .gitleaks.toml <fixture-repo>" {
		t.Errorf("portableArgs = %v", got)
	}
}

func TestInspectToolAllowList(t *testing.T) {
	t.Parallel()
	if _, err := inspectTool("aegisflow-e1-no-such-binary", "", ""); err == nil {
		t.Error("missing binary accepted")
	}
	// The test binary is a Go program from the aegisflow module: it must be refused.
	if _, err := inspectTool(os.Args[0], "", ""); err == nil || !strings.Contains(err.Error(), "refusing to run") {
		t.Errorf("non-gitleaks binary: err = %v", err)
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func TestMaterializeIsReproducible(t *testing.T) {
	t.Parallel()
	requireGit(t)
	ctx := context.Background()
	var heads []string
	var ds *Dataset
	for range 2 {
		var err error
		if ds, err = buildDataset(11, 1, 5); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := ds.materialize(ctx, dir); err != nil {
			t.Fatal(err)
		}
		heads = append(heads, ds.HeadCommit)

		count, err := runGit(ctx, dir, fixtureEpoch, "rev-list", "--count", "HEAD")
		if err != nil || count != strconv.Itoa(len(ds.Commits)) {
			t.Fatalf("commit count %q (err %v), want %d", count, err, len(ds.Commits))
		}
		for _, it := range ds.Items {
			if it.Commit == "" {
				t.Fatalf("%s has no commit", it.ID)
			}
			blob, err := runGit(ctx, dir, fixtureEpoch, "show", it.Commit+":"+it.File)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(blob, "\n")
			if strings.Join(lines[it.StartLine-1:it.EndLine], "\n") != strings.Join(it.doc.item, "\n") {
				t.Errorf("%s: committed lines differ from the ground truth span", it.ID)
			}
			if it.Variant == variantHistory {
				head, err := runGit(ctx, dir, fixtureEpoch, "show", "HEAD:"+it.File)
				if err != nil || it.RemovedIn == "" || strings.Contains(head, firstLine(it.doc.value)) {
					t.Errorf("%s: history-only secret still at HEAD (removed in %q, err %v)", it.ID, it.RemovedIn, err)
				}
			}
		}
	}
	if heads[0] != heads[1] {
		t.Errorf("HEAD differs between identical runs: %s vs %s", heads[0], heads[1])
	}
}

func TestRunGenerateOnlyWritesGroundTruthWithoutValues(t *testing.T) {
	t.Parallel()
	requireGit(t)
	out := filepath.Join(t.TempDir(), "results")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-generate-only", "-seed", "5", "-out", out}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	fixture := strings.TrimPrefix(firstLine(stdout.String()), "fixture: ")
	t.Cleanup(func() { _ = os.RemoveAll(fixture) })

	raw, err := os.ReadFile(filepath.Join(out, "ground-truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gt struct {
		Items []Item `json:"items"`
	}
	if err := json.Unmarshal(raw, &gt); err != nil || len(gt.Items) != 100 {
		t.Fatalf("ground truth: %d items, err %v", len(gt.Items), err)
	}
	ds, _ := buildDataset(5, 1, 12)
	for _, it := range ds.Items {
		if it.doc.value != "" && bytes.Contains(raw, []byte(firstLine(it.doc.value))) {
			t.Errorf("ground truth contains the value of %s", it.ID)
		}
	}
}

func TestRunUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"-modes", "git,ftp"}, {"-reps", "0"}, {"extra"}, {"-commits", "-1"}} {
		if code := run(context.Background(), args, io.Discard, io.Discard); code != exitUsage {
			t.Errorf("args %v: exit %d, want %d", args, code, exitUsage)
		}
	}
	if code := run(context.Background(), []string{"-h"}, io.Discard, io.Discard); code != exitOK {
		t.Errorf("-h: exit %d", code)
	}
}

func TestMarkdownReport(t *testing.T) {
	t.Parallel()
	ds, err := buildDataset(9, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	var findings []Finding
	for _, it := range ds.Items {
		if it.Type == "aws-access-key" || it.Type == "image-digest" {
			findings = append(findings, Finding{RuleID: "rule-" + it.Type, File: it.File, StartLine: it.StartLine, EndLine: it.StartLine})
		}
	}
	m := score(ScanRun{Mode: "dir", Findings: findings}, ds.Items)
	res := &Results{
		Parameters: Parameters{Seed: 9, Reps: 1, Commits: 4},
		Dataset:    datasetInfo(ds, "sha256:x"),
		Thresholds: Thresholds{RecallMin: thresholdRecall, PrecisionMin: thresholdPrecision, DetectMax: thresholdDetect},
		Verdict:    Verdict{Mode: "dir"},
		Modes:      []ModeResult{m},
		Notes:      notes(),
	}
	md := markdown(res, ds)
	for _, want := range []string{
		"| aws-access-key | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 80.0 % |",
		"| image-digest | 5/5 | 100.0 % |",
		"| rule-image-digest | 0 | 5 |",
		"Missed secrets:",
		"recall >= 0.90 **FAIL**",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
}
