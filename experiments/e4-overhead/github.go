package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	repoPattern     = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)
	workflowPattern = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+\.ya?ml|[0-9]+)$`)
	linkNextPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)
)

// errNotFound marks a 404 (for example a workflow file that does not exist on the default branch).
var errNotFound = errors.New("not found")

// Run is the subset of a GitHub Actions workflow run used by E4.
type Run struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	HeadSHA      string    `json:"head_sha"`
	HeadBranch   string    `json:"head_branch"`
	Event        string    `json:"event"`
	Status       string    `json:"status"`
	Conclusion   string    `json:"conclusion"`
	RunAttempt   int       `json:"run_attempt"`
	CreatedAt    time.Time `json:"created_at"`
	RunStartedAt time.Time `json:"run_started_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Job is the subset of a workflow job used by E4.
type Job struct {
	ID          int64     `json:"id"`
	RunID       int64     `json:"run_id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Conclusion  string    `json:"conclusion"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Labels      []string  `json:"labels"`
}

// client is a minimal, read-only GitHub REST client. The token is only ever sent to the
// configured API origin and is never logged or written to any output.
type client struct {
	base     *url.URL
	repo     string
	token    string
	http     *http.Client
	logger   *slog.Logger
	requests int
}

// parseAPIBase accepts https URLs, and plain http only for loopback hosts (local fakes in tests).
func parseAPIBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse -api: %w", err)
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !loopback)) {
		return nil, fmt.Errorf("-api must be an https URL (http only for loopback), got %q", raw)
	}
	return u, nil
}

func newClient(base *url.URL, repo, token string, logger *slog.Logger) *client {
	return &client{
		base:   base,
		repo:   repo,
		token:  token,
		http:   &http.Client{Timeout: 30 * time.Second},
		logger: logger,
	}
}

// get fetches one page and decodes it into v. It returns the absolute URL of the next page,
// if any (from the Link header), after checking that it stays on the API origin.
func (c *client) get(ctx context.Context, target *url.URL, v any) (*url.URL, error) {
	if target.Scheme != c.base.Scheme || target.Host != c.base.Host {
		return nil, fmt.Errorf("refusing request outside the API origin: %s", target.Redacted())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "aegisflow-e4-overhead")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	c.requests++
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", target.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", target.Path, err)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("GET %s: %w", target.Path, errNotFound)
	case (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) &&
		resp.Header.Get("X-RateLimit-Remaining") == "0":
		reset := resp.Header.Get("X-RateLimit-Reset")
		if sec, err := strconv.ParseInt(reset, 10, 64); err == nil {
			reset = time.Unix(sec, 0).UTC().Format(time.RFC3339)
		}
		return nil, fmt.Errorf("GET %s: rate limited until %s", target.Path, reset)
	case resp.StatusCode != http.StatusOK:
		var apiErr struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &apiErr)
		return nil, fmt.Errorf("GET %s: HTTP %d: %.200s", target.Path, resp.StatusCode, apiErr.Message)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return nil, fmt.Errorf("decode %s: %w", target.Path, err)
	}

	m := linkNextPattern.FindStringSubmatch(resp.Header.Get("Link"))
	if m == nil {
		return nil, nil
	}
	next, err := url.Parse(m[1])
	if err != nil {
		return nil, fmt.Errorf("parse Link header: %w", err)
	}
	return next, nil
}

func (c *client) endpoint(path string, q url.Values) *url.URL {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + "/repos/" + c.repo + path
	u.RawQuery = q.Encode()
	return &u
}

// listRuns returns up to limit runs of one workflow (newest first) matching the query.
func (c *client) listRuns(ctx context.Context, workflow string, q url.Values, limit int) ([]Run, error) {
	q.Set("per_page", strconv.Itoa(min(100, max(limit, 1))))
	next := c.endpoint("/actions/workflows/"+workflow+"/runs", q) // url.URL escapes Path
	var runs []Run
	for next != nil && len(runs) < limit {
		var page struct {
			WorkflowRuns []Run `json:"workflow_runs"`
		}
		var err error
		if next, err = c.get(ctx, next, &page); err != nil {
			return nil, err
		}
		if len(page.WorkflowRuns) == 0 {
			break
		}
		runs = append(runs, page.WorkflowRuns...)
	}
	return runs[:min(len(runs), limit)], nil
}

// listJobs returns every job of the latest attempt of a run.
func (c *client) listJobs(ctx context.Context, runID int64) ([]Job, error) {
	next := c.endpoint("/actions/runs/"+strconv.FormatInt(runID, 10)+"/jobs", url.Values{
		"filter": {"latest"}, "per_page": {"100"},
	})
	var jobs []Job
	for next != nil {
		var page struct {
			Jobs []Job `json:"jobs"`
		}
		var err error
		if next, err = c.get(ctx, next, &page); err != nil {
			return nil, err
		}
		if len(page.Jobs) == 0 {
			break
		}
		jobs = append(jobs, page.Jobs...)
	}
	return jobs, nil
}
