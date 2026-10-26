package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Item is one ground-truth entry: a seeded secret or a decoy. Values are never stored; only
// their SHA-256 and a 4-character preview.
type Item struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`                // "secret" or "decoy"
	Type        string `json:"type"`                // secret type ID or decoy kind ID
	Resembles   string `json:"resembles,omitempty"` // decoys: the secret type they imitate
	Variant     string `json:"variant,omitempty"`   // secrets: plain|config|base64|split|history
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	CommitIndex int    `json:"commit_index"`
	Commit      string `json:"commit"`
	RemovedIn   string `json:"removed_in,omitempty"`
	InFinalTree bool   `json:"in_final_tree"`
	ValueSHA256 string `json:"value_sha256"`
	Preview     string `json:"preview"`

	doc doc
}

const (
	kindSecret = "secret"
	kindDecoy  = "decoy"

	// decoysPerKind is the number of decoys per decoy kind and repetition: 10 kinds x 5 = 50
	// decoys per repetition, matching the 50 secrets (10 types x 5 variants).
	decoysPerKind = 5
)

type fileWrite struct {
	path    string
	content string
}

type commitPlan struct {
	Index   int
	Message string
	SHA     string
	writes  []fileWrite
	added   []*Item
	removed []*Item
}

// Dataset is the generated fixture: ground truth plus the commit plan that produces the repo.
type Dataset struct {
	Seed           int64
	Reps           int
	Items          []*Item
	Commits        []*commitPlan
	ManifestSHA256 string // hash of every planned write, independent of git
	HeadCommit     string // set by materialize; deterministic for a given git object format
}

// buildDataset generates reps x (10 types x 5 variants) secrets and reps x 50 decoys and spreads
// them over `commits` feature commits on top of a skeleton commit.
func buildDataset(seed int64, reps, commits int) (*Dataset, error) {
	if reps < 1 || commits < 1 {
		return nil, fmt.Errorf("reps (%d) and commits (%d) must be >= 1", reps, commits)
	}
	g := newGen(seed)
	for _, w := range skeleton() {
		g.paths[w.path] = true
	}
	ds := &Dataset{Seed: seed, Reps: reps}

	for range reps {
		for _, st := range secretTypes() {
			for _, v := range variants {
				d := renderSecret(g, st, v)
				ds.Items = append(ds.Items, &Item{Kind: kindSecret, Type: st.ID, Variant: v, doc: d})
			}
		}
	}
	for rep := range reps * decoysPerKind {
		for _, dk := range decoyKinds() {
			d, resembles := dk.render(g, rep)
			ds.Items = append(ds.Items, &Item{Kind: kindDecoy, Type: dk.ID, Resembles: resembles, doc: d})
		}
	}

	var nSecret, nDecoy int
	for _, it := range ds.Items {
		if it.Kind == kindSecret {
			nSecret++
			it.ID = fmt.Sprintf("s%03d", nSecret)
		} else {
			nDecoy++
			it.ID = fmt.Sprintf("d%03d", nDecoy)
		}
		it.File = it.doc.path
		it.StartLine, it.EndLine = it.doc.span()
		it.InFinalTree = it.Variant != variantHistory
		value := it.doc.value
		if value == "" { // decoys: the item lines are the value
			value = strings.Join(it.doc.item, "\n")
		}
		it.ValueSHA256 = valueFingerprint(value)
		it.Preview = preview(value)
	}

	// Spread items over the feature commits in a seeded random order.
	order := slices.Clone(ds.Items)
	g.r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	plans := make([]*commitPlan, commits+2)
	for i := range plans {
		plans[i] = &commitPlan{Index: i}
	}
	plans[0].writes = skeleton()
	for i, it := range order {
		c := 1 + i%commits
		it.CommitIndex = c
		plans[c].added = append(plans[c].added, it)
		plans[c].writes = append(plans[c].writes, fileWrite{it.File, content(it.doc.lines())})
		if it.Variant == variantHistory {
			r := min(c+1, commits+1)
			plans[r].removed = append(plans[r].removed, it)
			plans[r].writes = append(plans[r].writes, fileWrite{it.File, content(it.doc.sanitized())})
		}
	}
	if len(plans[commits+1].writes) == 0 {
		plans = plans[:commits+1]
	}

	h := sha256.New()
	for _, p := range plans {
		slices.SortFunc(p.writes, func(a, b fileWrite) int { return strings.Compare(a.path, b.path) })
		p.Message = commitMessage(p)
		fmt.Fprintf(h, "commit\x00%d\x00%s\x00", p.Index, p.Message)
		for _, w := range p.writes {
			fmt.Fprintf(h, "%s\x00%s\x00", w.path, w.content)
		}
	}
	ds.Commits = plans
	ds.ManifestSHA256 = "sha256:" + hexEncode(h.Sum(nil))
	return ds, nil
}

func commitMessage(p *commitPlan) string {
	switch {
	case p.Index == 0:
		return "chore: initial service skeleton"
	case len(p.added) == 0:
		return "fix(security): remove hardcoded credentials"
	}
	first := p.added[0].File
	for _, it := range p.added {
		first = min(first, it.File)
	}
	msg := "feat: add " + first
	if n := len(p.added) - 1; n > 0 {
		msg += " (+" + strconv.Itoa(n) + " files)"
	}
	if len(p.removed) > 0 {
		msg += "\n\nAlso removes hardcoded credentials that were committed earlier."
	}
	return msg
}

func skeleton() []fileWrite {
	return []fileWrite{
		{"README.md", "# contoso-platform\n\nInternal services monorepo (synthetic E1 fixture generated by AegisFlow).\n"},
		{"go.mod", "module example.com/contoso/platform\n\ngo 1.27.0\n"},
		{".gitignore", "/bin/\n.env\n"},
		{"cmd/app/main.go", "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"contoso platform\")\n}\n"},
		{"Makefile", ".PHONY: test\ntest:\n\tgo test ./...\n"},
	}
}

// ---------------------------------------------------------------------------------------------
// Materialisation with the git CLI

// fixtureEpoch is the author/committer date of the skeleton commit; later commits follow at fixed
// intervals so commit SHAs are reproducible.
var fixtureEpoch = time.Date(2026, time.January, 5, 9, 0, 0, 0, time.UTC)

// scrubbedEnv returns the process environment without variables that could redirect git or
// gitleaks (GIT_DIR, GITLEAKS_CONFIG, ...), plus the given overrides.
func scrubbedEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GIT_") || strings.HasPrefix(name, "GITLEAKS_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

func gitEnv(when time.Time) []string {
	date := when.Format(time.RFC3339)
	return scrubbedEnv(
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=E1 Fixture",
		"GIT_AUTHOR_EMAIL=e1-fixture@example.invalid",
		"GIT_COMMITTER_NAME=E1 Fixture",
		"GIT_COMMITTER_EMAIL=e1-fixture@example.invalid",
		"GIT_AUTHOR_DATE="+date,
		"GIT_COMMITTER_DATE="+date,
		"LC_ALL=C",
	)
}

func runGit(ctx context.Context, dir string, when time.Time, args ...string) (string, error) {
	// Fixed binary, arguments built by this program, no shell involved.
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // G204: see comment above
	cmd.Dir = dir
	cmd.Env = gitEnv(when)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// materialize writes the planned commits into dir (which must be empty) as a git repository.
func (ds *Dataset) materialize(ctx context.Context, dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open fixture dir: %w", err)
	}
	defer func() { _ = root.Close() }()

	if _, err := runGit(ctx, dir, fixtureEpoch, "init", "-q", "-b", "main"); err != nil {
		return err
	}
	for _, p := range ds.Commits {
		for _, w := range p.writes {
			if err := root.MkdirAll(path.Dir(w.path), 0o750); err != nil {
				return fmt.Errorf("mkdir for %s: %w", w.path, err)
			}
			if err := root.WriteFile(w.path, []byte(w.content), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", w.path, err)
			}
		}
		when := fixtureEpoch.Add(time.Duration(p.Index) * 97 * time.Minute)
		if _, err := runGit(ctx, dir, when, "add", "-A"); err != nil {
			return err
		}
		if _, err := runGit(ctx, dir, when, "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", p.Message); err != nil {
			return err
		}
		sha, err := runGit(ctx, dir, when, "rev-parse", "HEAD")
		if err != nil {
			return err
		}
		p.SHA = sha
		for _, it := range p.added {
			it.Commit = sha
		}
		for _, it := range p.removed {
			it.RemovedIn = sha
		}
		ds.HeadCommit = sha
	}
	return nil
}

func (ds *Dataset) counts() (secrets, decoys int) {
	for _, it := range ds.Items {
		if it.Kind == kindSecret {
			secrets++
		} else {
			decoys++
		}
	}
	return secrets, decoys
}
