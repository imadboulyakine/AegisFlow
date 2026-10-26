package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDatasetIsDeterministic(t *testing.T) {
	t.Parallel()
	a, err := buildDataset(42, 1, 12)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := buildDataset(42, 1, 12)
	c, _ := buildDataset(43, 1, 12)
	if a.ManifestSHA256 != b.ManifestSHA256 {
		t.Errorf("same seed, different manifests: %s vs %s", a.ManifestSHA256, b.ManifestSHA256)
	}
	if a.ManifestSHA256 == c.ManifestSHA256 {
		t.Error("different seeds produced the same manifest")
	}
	_, sumA, _ := groundTruthJSON(a)
	_, sumB, _ := groundTruthJSON(b)
	if sumA != sumB {
		t.Error("same seed, different ground truth")
	}
}

func TestDatasetDesign(t *testing.T) {
	t.Parallel()
	ds, err := buildDataset(20261026, 2, 7)
	if err != nil {
		t.Fatal(err)
	}
	secrets, decoys := ds.counts()
	if secrets != 100 || decoys != 100 {
		t.Fatalf("counts = %d secrets, %d decoys; want 100/100 for reps=2", secrets, decoys)
	}
	if n := len(secretTypes()); n < 10 {
		t.Errorf("only %d secret types, ROADMAP requires >= 10", n)
	}

	cells := map[string]int{}
	files := map[string]bool{}
	for _, it := range ds.Items {
		if files[it.File] {
			t.Errorf("file %s holds more than one item", it.File)
		}
		files[it.File] = true

		lines := it.doc.lines()
		if it.StartLine < 1 || it.EndLine < it.StartLine || it.EndLine > len(lines) {
			t.Fatalf("%s: span %d-%d outside %d lines", it.ID, it.StartLine, it.EndLine, len(lines))
		}
		if got := strings.Join(lines[it.StartLine-1:it.EndLine], "\n"); got != strings.Join(it.doc.item, "\n") {
			t.Errorf("%s: span does not cover the item", it.ID)
		}
		if !strings.HasPrefix(it.ValueSHA256, "sha256:") || len(it.Preview) > 7 {
			t.Errorf("%s: fingerprint %q / preview %q", it.ID, it.ValueSHA256, it.Preview)
		}
		if it.Kind == kindDecoy {
			if it.Resembles == "" || it.CommitIndex < 1 {
				t.Errorf("%s: decoy without resembles/commit", it.ID)
			}
			continue
		}
		cells[it.Type+"/"+it.Variant]++
		if it.InFinalTree == (it.Variant == variantHistory) {
			t.Errorf("%s: in_final_tree=%v for variant %s", it.ID, it.InFinalTree, it.Variant)
		}
		first := firstLine(it.doc.value)
		switch it.Variant {
		case variantHistory:
			if strings.Contains(content(it.doc.sanitized()), first) {
				t.Errorf("%s: sanitized file still contains the credential", it.ID)
			}
			fallthrough
		case variantPlain, variantConfig:
			if !strings.Contains(content(lines), first) {
				t.Errorf("%s: credential not written verbatim", it.ID)
			}
		case variantSplit:
			if strings.Contains(content(lines), first) && !strings.Contains(first, "PRIVATE") {
				t.Errorf("%s: split variant contains the value in one piece", it.ID)
			}
		case variantBase64:
			if _, err := base64.StdEncoding.DecodeString(first); err != nil {
				t.Errorf("%s: base64 variant value does not decode: %v", it.ID, err)
			}
		}
	}
	for _, st := range secretTypes() {
		for _, v := range variants {
			if n := cells[st.ID+"/"+v]; n != 2 {
				t.Errorf("cell %s/%s has %d secrets, want 2 (balanced design)", st.ID, v, n)
			}
		}
	}
	if last := ds.Commits[len(ds.Commits)-1]; last.Index != len(ds.Commits)-1 || len(last.writes) == 0 {
		t.Errorf("commit plan has an empty or misnumbered tail: %+v", last)
	}
}

func TestBuildDatasetRejectsBadParameters(t *testing.T) {
	t.Parallel()
	if _, err := buildDataset(1, 0, 3); err == nil {
		t.Error("reps=0 accepted")
	}
	if _, err := buildDataset(1, 1, 0); err == nil {
		t.Error("commits=0 accepted")
	}
}

// TestCredentialFormats checks that generated values follow the vendors' published formats, so
// the benchmark measures detection of realistic credentials.
func TestCredentialFormats(t *testing.T) {
	t.Parallel()
	dashes := strings.Repeat("-", 5)
	formats := map[string][]*regexp.Regexp{
		"aws-access-key":                  {regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`), regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)},
		"github-pat-classic":              {regexp.MustCompile(`^ghp_[A-Za-z0-9]{36}$`)},
		"github-pat-fine-grained":         {regexp.MustCompile(`^github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}$`)},
		"azure-storage-connection-string": {regexp.MustCompile(`^DefaultEndpointsProtocol=https;AccountName=st[a-z0-9]{12};AccountKey=[A-Za-z0-9+/]{86}==;EndpointSuffix=core\.windows\.net$`)},
		"azure-entra-client-secret":       {regexp.MustCompile(`^[A-Za-z0-9]{3}[0-9]Q~[A-Za-z0-9_~.-]{34}$`)},
		"slack-bot-token":                 {regexp.MustCompile(`^xoxb-[0-9]{11}-[0-9]{13}-[A-Za-z0-9]{24}$`)},
		"private-key-pem":                 {regexp.MustCompile(`(?s)^` + dashes + `BEGIN (RSA|EC|OPENSSH) PRIVATE KEY` + dashes + `\n[A-Za-z0-9+/=\n]+\n` + dashes + `END (RSA|EC|OPENSSH) PRIVATE KEY` + dashes + `$`)},
		"jwt":                             {regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$`)},
		"generic-api-key":                 {regexp.MustCompile(`^[A-Za-z0-9]{32}$`)},
		"postgres-uri":                    {regexp.MustCompile(`^postgres:\/\/[a-z_]+:[A-Za-z0-9._~-]{22}@psql-[a-z]+-prod\.postgres\.database\.azure\.com:5432/[a-z]+\?sslmode=require$`)},
	}
	g := newGen(7)
	for _, st := range secretTypes() {
		want, ok := formats[st.ID]
		if !ok {
			t.Errorf("no format check for type %s", st.ID)
			continue
		}
		for range 30 {
			fields := st.generate(g)
			if len(fields) != len(want) {
				t.Fatalf("%s: %d fields, want %d", st.ID, len(fields), len(want))
			}
			for i, f := range fields {
				if !want[i].MatchString(f.Value) {
					t.Errorf("%s field %s has an unexpected format (preview %s)", st.ID, f.Key, preview(f.Value))
				}
			}
		}
	}
	header, _, _ := strings.Cut(genJWT(g)[0].Value, ".")
	if raw, _ := base64.RawURLEncoding.DecodeString(header); string(raw) != `{"alg":"HS256","typ":"JWT"}` {
		t.Errorf("JWT header = %s", raw)
	}
}

// TestSourceHasNoCredentialLiterals guards the hygiene rule of this package: no value in the
// source tree may look like a real credential (the repository's own gitleaks gate scans it).
func TestSourceHasNoCredentialLiterals(t *testing.T) {
	t.Parallel()
	dashes := strings.Repeat("-", 5)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		regexp.MustCompile(`github_pat_\w{82}`),
		regexp.MustCompile(`AKIA[A-Z2-7]{16}`),
		regexp.MustCompile(`xox[abp]-[0-9]{10,}`),
		regexp.MustCompile(dashes + `BEGIN[A-Z ]*PRIVATE KEY`),
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ`),
		regexp.MustCompile(`AccountKey=[A-Za-z0-9+/]{20,}`),
		regexp.MustCompile(`[A-Za-z0-9]{3}[0-9]Q~[A-Za-z0-9_~.-]{30,}`),
		regexp.MustCompile(`postgres://[^:\s]+:[A-Za-z0-9._~-]{16,}@`), // generated passwords are 22 chars; doc placeholders are short
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range patterns {
			if loc := p.FindIndex(src); loc != nil {
				line := strings.Count(string(src[:loc[0]]), "\n") + 1
				t.Errorf("%s:%d contains a credential-shaped literal (pattern %s)", f, line, p)
			}
		}
	}
}

func TestSplitValue(t *testing.T) {
	t.Parallel()
	g := newGen(3)
	for _, n := range []int{20, 36, 59, 88, 140} {
		v := g.str(alnumChars, n)
		for range 20 {
			parts := splitValue(g, v)
			if strings.Join(parts, "") != v {
				t.Fatalf("parts of a %d-char value do not rejoin", n)
			}
			wantParts := 2
			if n > 60 {
				wantParts = 3
			}
			if len(parts) != wantParts {
				t.Errorf("len %d: %d parts, want %d", n, len(parts), wantParts)
			}
			for _, p := range parts {
				if len(p) < 4 {
					t.Errorf("len %d: fragment shorter than 4 chars", n)
				}
			}
		}
	}
	pem := splitValue(g, "a\nb\nc")
	if strings.Join(pem, "|") != `a\n|b\n|c\n` {
		t.Errorf("multi-line split = %q", pem)
	}
}

func TestPathAllocatorAvoidsCollisions(t *testing.T) {
	t.Parallel()
	g := newGen(1)
	got := []string{g.path("config/app.prod.yaml"), g.path("config/app.prod.yaml"), g.path("ops/ssh/key"), g.path("ops/ssh/key")}
	want := []string{"config/app.prod.yaml", "config/app.prod_2.yaml", "ops/ssh/key", "ops/ssh/key_2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("paths = %v, want %v", got, want)
	}
}

func TestIdentifierStyles(t *testing.T) {
	t.Parallel()
	if got := camelCase("AWS_ACCESS_KEY_ID"); got != "awsAccessKeyId" {
		t.Errorf("camelCase = %s", got)
	}
	if got := pascalCase("GITHUB_TOKEN"); got != "GithubToken" {
		t.Errorf("pascalCase = %s", got)
	}
	if got := snakeCase("DATABASE_URL"); got != "database_url" {
		t.Errorf("snakeCase = %s", got)
	}
	if upperFirst("") != "" {
		t.Error("upperFirst of empty string")
	}
}
