// Package intel provides AegisFlow's vulnerability-intelligence feeds: the CISA Known Exploited
// Vulnerabilities (KEV) catalogue and FIRST's Exploit Prediction Scoring System (EPSS).
//
// The risk engine (internal/risk, ADR-012) needs, for every CVE, the probability of exploitation
// in the next 30 days (EPSS) and whether exploitation has been observed in the wild (KEV). This
// package:
//
//   - parses the KEV JSON catalogue (ParseKEV) and fetches it (KEVClient);
//   - parses EPSS API v1 responses (ParseEPSSResponse) and the daily bulk CSV, gzip or plain
//     (ParseEPSSCSV), and fetches scores in batches of up to 100 CVEs (EPSSClient);
//   - combines both into an immutable Snapshot that answers lookups by CVE and records the
//     provenance of each feed (catalogue version, EPSS model version and score date, source,
//     fetch time), so experiment results can freeze the exact intelligence they used
//     (Snapshot.WriteJSON / ReadSnapshot, Experiment E2);
//   - offers MemoryStore, a concurrency-safe holder that swaps snapshots atomically.
//
// Feeds are untrusted network input: every parser enforces size and row limits, validates CVE
// identifiers, dates and probability ranges, rejects empty or inconsistent catalogues (an empty
// feed must never silently erase exploitation signal) and never panics. HTTP clients bound
// response sizes, honour context cancellation and retry 429/5xx responses with bounded
// exponential backoff. All tests run offline against httptest servers and fixtures.
package intel
