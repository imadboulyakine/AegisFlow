package normalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// govulncheckMessageKeys are the top-level keys of govulncheck's JSON protocol messages.
var govulncheckMessageKeys = map[string]bool{
	"config": true, "progress": true, "SBOM": true, "osv": true, "finding": true,
}

// Detect sniffs the evidence format from content. Only the first top-level JSON value is
// examined and only exact (case-sensitive) key names are considered:
//
//   - CycloneDX: "bomFormat": "CycloneDX"
//   - SPDX: "spdxVersion": "SPDX-…"
//   - OpenVEX: "@context": "https://openvex.dev/ns…"
//   - SARIF: "runs" plus a "version" or a "$schema" mentioning sarif
//   - Grype: "matches" plus "descriptor"
//   - govulncheck: a single-key protocol message ("config", "progress", "SBOM", "osv", "finding")
//
// Detect does not validate the document; Parse does. Detect does not limit the input size
// either: callers must bound data (Parse and ParseBytes do).
func Detect(data []byte) (evidence.Format, error) {
	data = trimBOM(data)
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", fmt.Errorf("%w: not a JSON object (only JSON encodings are supported)", ErrUnknownFormat)
	}
	var top map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(trimmed)).Decode(&top); err != nil {
		return "", fmt.Errorf("%w: malformed JSON: %w", ErrUnknownFormat, err)
	}
	str := func(key string) string {
		var s string
		if raw, ok := top[key]; ok {
			_ = json.Unmarshal(raw, &s) // non-string values simply do not match
		}
		return s
	}
	has := func(key string) bool {
		raw, ok := top[key]
		return ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
	}
	switch {
	case str("bomFormat") == "CycloneDX":
		return evidence.FormatCycloneDX, nil
	case strings.HasPrefix(str("spdxVersion"), "SPDX-"):
		return evidence.FormatSPDX, nil
	case strings.HasPrefix(str("@context"), "https://openvex.dev/ns"):
		return evidence.FormatOpenVEX, nil
	case has("runs") && (has("version") || strings.Contains(strings.ToLower(str("$schema")), "sarif")):
		return evidence.FormatSARIF, nil
	case has("matches") && has("descriptor"):
		return evidence.FormatGrype, nil
	case len(top) == 1 && isGovulncheckMessage(top):
		return evidence.FormatGovulncheck, nil
	}
	return "", fmt.Errorf("%w: no known format markers", ErrUnknownFormat)
}

func isGovulncheckMessage(top map[string]json.RawMessage) bool {
	for k := range top {
		return govulncheckMessageKeys[k]
	}
	return false
}
