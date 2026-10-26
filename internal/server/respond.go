package server

import (
	"encoding/json"
	"net/http"
)

const (
	contentTypeJSON    = "application/json"
	contentTypeProblem = "application/problem+json"
)

// problem is an RFC 9457 "Problem Details for HTTP APIs" body.
type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance,omitempty"`
	RequestID string `json:"requestId,omitempty"`
}

// writeJSON writes v as a non-cacheable JSON response. Encoding happens before the
// header is written so a marshalling bug turns into a clean 500, not a truncated body.
func writeJSON(w http.ResponseWriter, status int, contentType string, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

// writeProblem writes an RFC 9457 problem response for the given status.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, detail string) {
	writeJSON(w, status, contentTypeProblem, problem{
		Type:      "about:blank",
		Title:     http.StatusText(status),
		Status:    status,
		Detail:    detail,
		Instance:  r.URL.Path,
		RequestID: RequestIDFromContext(r.Context()),
	})
}
