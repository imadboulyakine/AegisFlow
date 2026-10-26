// Shared test fixtures for the findings API (shapes match the Go server's JSON).

export const sampleFinding = {
  id: 7,
  artifactId: 3,
  kind: "vulnerability",
  title: "x/text DoS",
  severity: "high",
  status: "open",
  tools: ["govulncheck", "grype"],
  vulnerability: { id: "CVE-2022-32149", aliases: ["GO-2022-1059"], severity: "high" },
  component: { purl: "pkg:golang/golang.org/x/text@v0.3.7", name: "golang.org/x/text", version: "v0.3.7", direct: true },
  fixedVersions: ["v0.3.8"],
  reachability: "called",
  risk: {
    score: 76,
    tier: "P1",
    action: "block",
    reason: "P1 (KEV override): CVSS 7.5, EPSS 0.60, in CISA KEV since 2026-03-02, reachable (called), internet-facing",
    flags: ["kev-override"],
    scoredAt: "2026-10-26T08:00:00Z",
  },
  firstSeenRun: 1,
  lastSeenRun: 2,
  updatedAt: "2026-10-26T08:00:00Z",
};

export const sampleExplanation = {
  scorer: "aegisflow-risk/v1",
  score: 76,
  tier: "P1",
  reason: "P1 …",
  flags: ["kev-override"],
  factors: [
    { name: "cvss", kind: "additive", raw: "7.5", normalized: 0.75, weight: 0.4, contribution: 30, source: "CVSS v3.1" },
    { name: "reachability", kind: "multiplier", raw: "called", normalized: 1, weight: 1, contribution: 0, source: "govulncheck", note: "symbol called" },
  ],
};
