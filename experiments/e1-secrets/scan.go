package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// gitleaksExitLeaks is passed as --exit-code so "leaks found" is distinguishable from a
	// failure (gitleaks exits 1 on fatal errors).
	gitleaksExitLeaks = 3
	// gitleaksModule is the Go main module every accepted scanner binary must embed.
	gitleaksModule = "github.com/zricethezav/gitleaks/v8"
)

// ToolInfo identifies the exact scanner binary and configuration used for a run.
type ToolInfo struct {
	Name         string `json:"name"`
	Path         string `json:"-"`
	Module       string `json:"module"`
	Version      string `json:"version"`
	ModuleSum    string `json:"module_sum,omitempty"`
	GoVersion    string `json:"go_version,omitempty"`
	BinarySHA256 string `json:"binary_sha256"`
	Config       string `json:"config"`
	ConfigSHA256 string `json:"config_sha256,omitempty"`
	configPath   string
}

// inspectTool resolves the gitleaks binary and reads its embedded Go build info, so results
// record the module version that was actually executed, not just a label. Only a binary built
// from the gitleaks v8 module (and, if wantVersion is set, exactly that version) is accepted:
// this is the allow-list that makes executing an operator-supplied path acceptable.
func inspectTool(bin, wantVersion, config string) (ToolInfo, error) {
	p, err := exec.LookPath(bin)
	if err != nil {
		return ToolInfo{}, fmt.Errorf("find gitleaks %q: %w", bin, err)
	}
	if p, err = filepath.Abs(p); err != nil {
		return ToolInfo{}, fmt.Errorf("resolve gitleaks path: %w", err)
	}
	bi, err := buildinfo.ReadFile(p)
	if err != nil {
		return ToolInfo{}, fmt.Errorf("read Go build info of %s (not a Go-built gitleaks?): %w", p, err)
	}
	if bi.Main.Path != gitleaksModule {
		return ToolInfo{}, fmt.Errorf("refusing to run %s: main module is %q, want %q", p, bi.Main.Path, gitleaksModule)
	}
	if wantVersion != "" && bi.Main.Version != wantVersion {
		return ToolInfo{}, fmt.Errorf("refusing to run %s: gitleaks %s, want %s", p, bi.Main.Version, wantVersion)
	}
	info := ToolInfo{
		Name: "gitleaks", Path: p, Module: bi.Main.Path, Version: bi.Main.Version,
		ModuleSum: bi.Main.Sum, GoVersion: bi.GoVersion, Config: "built-in default",
	}
	if info.BinarySHA256, err = fileSHA256(p); err != nil {
		return ToolInfo{}, err
	}
	if config != "" {
		abs, err := filepath.Abs(config)
		if err != nil {
			return ToolInfo{}, fmt.Errorf("resolve config path: %w", err)
		}
		info.configPath, info.Config = abs, filepath.Base(abs)
		if info.ConfigSHA256, err = fileSHA256(abs); err != nil {
			return ToolInfo{}, err
		}
	}
	return info, nil
}

func fileSHA256(p string) (string, error) {
	// p is the operator-chosen gitleaks binary or config: it is only read, to record its digest.
	f, err := os.Open(filepath.Clean(p)) //nolint:gosec // G703: reading an operator-supplied path is the intent
	if err != nil {
		return "", fmt.Errorf("open %s: %w", p, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", p, err)
	}
	return "sha256:" + hexEncode(h.Sum(nil)), nil
}

// Finding is the subset of a gitleaks JSON report entry the benchmark needs. Reports are
// produced with --redact, so no secret value is ever read or stored.
type Finding struct {
	RuleID    string `json:"RuleID"`
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Commit    string `json:"Commit"`
}

// ScanRun is one gitleaks invocation.
type ScanRun struct {
	Mode     string        `json:"mode"`
	Args     []string      `json:"args"`
	Runtime  time.Duration `json:"-"`
	Findings []Finding     `json:"-"`
}

// runGitleaks scans repoDir in the given mode ("git": every commit of the history, like the
// nightly job and the PR diff scan; "dir": the working tree only) and parses the report.
func runGitleaks(ctx context.Context, tool ToolInfo, mode, repoDir, reportPath string) (ScanRun, error) {
	args := []string{
		mode, "--no-banner", "--redact", "--log-level", "warn",
		"--report-format", "json", "--report-path", reportPath,
		"--exit-code", strconv.Itoa(gitleaksExitLeaks),
		"--ignore-gitleaks-allow", "--gitleaks-ignore-path", repoDir,
	}
	if tool.configPath != "" {
		args = append(args, "--config", tool.configPath)
	}
	args = append(args, repoDir)

	// tool.Path is an absolute path whose embedded build info was verified by inspectTool to be the
	// gitleaks v8 module; arguments are built here and passed as argv (no shell).
	cmd := exec.CommandContext(ctx, tool.Path, args...) //nolint:gosec // nosemgrep: go-exec-nonconstant-command -- path verified as a gitleaks v8 build by inspectTool
	cmd.Dir = repoDir
	cmd.Env = scrubbedEnv("GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "NO_COLOR=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out

	start := time.Now()
	err := cmd.Run()
	run := ScanRun{Mode: mode, Runtime: time.Since(start), Args: portableArgs(args, repoDir, reportPath)}
	var exitErr *exec.ExitError
	if err != nil && (!errors.As(err, &exitErr) || exitErr.ExitCode() != gitleaksExitLeaks) {
		return run, fmt.Errorf("gitleaks %s: %w: %s", mode, err, lastLines(out.String(), 5))
	}

	raw, err := os.ReadFile(filepath.Clean(reportPath))
	if err != nil {
		return run, fmt.Errorf("read gitleaks report: %w", err)
	}
	if run.Findings, err = parseReport(raw, repoDir); err != nil {
		return run, err
	}
	return run, nil
}

func parseReport(raw []byte, repoDir string) ([]Finding, error) {
	var findings []Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}
	for i := range findings {
		f := &findings[i]
		if filepath.IsAbs(f.File) {
			if rel, err := filepath.Rel(repoDir, f.File); err == nil {
				f.File = rel
			}
		}
		f.File = filepath.ToSlash(strings.TrimPrefix(f.File, "./"))
		f.EndLine = max(f.EndLine, f.StartLine)
	}
	return findings, nil
}

// portableArgs replaces machine-specific paths so the recorded command is comparable across runs.
func portableArgs(args []string, repoDir, reportPath string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		switch a {
		case repoDir:
			out[i] = "<fixture-repo>"
		case reportPath:
			out[i] = filepath.Base(reportPath)
		default:
			if strings.HasPrefix(a, string(filepath.Separator)) {
				a = filepath.Base(a)
			}
			out[i] = a
		}
	}
	return out
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], " | ")
}
