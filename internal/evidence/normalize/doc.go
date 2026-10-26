// Package normalize converts raw CI evidence into AegisFlow's tool-agnostic domain model
// (evidence.Document).
//
// It is the first stage of the ingest pipeline: the API stores the raw, content-addressed evidence
// file and then calls Parse (or ParseBytes) to obtain normalized components, findings and VEX
// statements that the store, risk engine and policy engine consume.
//
// Supported inputs (JSON encodings only):
//
//   - CycloneDX 1.4–1.7 (SBOM, optionally with a vulnerabilities/VEX section)
//   - SPDX 2.2 and 2.3
//   - SARIF 2.1.0 (secret, code, IaC/workflow and DAST scanners)
//   - Grype JSON (`grype -o json`)
//   - govulncheck JSON message stream (`govulncheck -format json`, protocol v1)
//   - OpenVEX 0.2.0
//
// Every input is treated as untrusted: the reader is size-limited, the JSON is pre-validated
// (nesting depth, duplicate or case-colliding object keys, trailing data), known structure is
// validated while unknown fields are ignored, and the number and total size of normalized items
// are bounded so that a small document cannot expand into a huge one.
//
// Findings carry deterministic fingerprints (VulnFingerprint, LocationFingerprint) and are
// deduplicated within a document (Dedupe), merging the tools that reported them.
package normalize
