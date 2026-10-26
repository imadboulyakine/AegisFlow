package server

import (
	"net/http"
)

type statusBody struct {
	Status string `json:"status"`
}

// handleHealthz is the liveness probe: the process is up and serving HTTP.
// It must stay dependency-free so a slow database never gets the pod restarted.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, contentTypeJSON, statusBody{Status: "ok"})
}

// handleReadyz is the readiness probe: 503 while starting or draining for shutdown.
// Later phases will add dependency checks (e.g. PostgreSQL) here, not in /healthz.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, contentTypeJSON, statusBody{Status: "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, contentTypeJSON, statusBody{Status: "ready"})
}

// handleVersion serves build metadata injected at link time.
func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, contentTypeJSON, s.version)
}

// apiErrors routes /api requests through mux and renders the mux's own 404/405
// answers as RFC 9457 problem JSON, so API clients never receive HTML or plain text.
func apiErrors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, pattern := mux.Handler(r)
		if pattern != "" {
			h.ServeHTTP(w, r)
			return
		}
		// No route matched: let the mux decide between 404 and 405 (and compute Allow),
		// capture its decision, then answer with a problem document instead.
		probe := &statusCapture{header: http.Header{}}
		h.ServeHTTP(probe, r)
		status := probe.status
		detail := "No API resource matches this path."
		if status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", probe.header.Get("Allow"))
			detail = "The resource does not support this method."
		} else {
			status = http.StatusNotFound
		}
		writeProblem(w, r, status, detail)
	})
}

// statusCapture is a throwaway ResponseWriter that records only status and headers.
type statusCapture struct {
	header http.Header
	status int
}

func (c *statusCapture) Header() http.Header { return c.header }

func (c *statusCapture) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}

func (c *statusCapture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return len(b), nil
}
