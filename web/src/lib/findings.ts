// Typed client for the read-only findings API (GET /api/v1/findings, GET /api/v1/findings/{id}).
// Responses are validated at runtime: the UI never trusts the shape of a network payload.
import { defaultFetcher, type Fetcher } from "./api";

export type Tier = "P1" | "P2" | "P3";
export type FindingStatus = "open" | "fixed" | "vex_not_affected" | "accepted";

export interface RiskFactor {
  name: string;
  kind: string;
  raw: string;
  normalized: number;
  weight: number;
  contribution: number;
  source: string;
  note?: string;
}

/** The risk engine's stored result (risk.Result), present on the detail endpoint only. */
export interface RiskExplanation {
  scorer: string;
  score: number;
  tier: string;
  reason: string;
  flags: string[];
  factors: RiskFactor[];
}

export interface FindingRisk {
  score: number;
  tier: Tier;
  action: string;
  reason: string;
  flags: string[];
  scoredAt: string;
  explanation?: RiskExplanation;
}

export interface CVSSRating {
  version: string;
  vector?: string;
  baseScore: number;
}

export interface FindingVulnerability {
  id: string;
  aliases: string[];
  severity: string;
  summary?: string;
  cvss?: CVSSRating[];
  cwes?: string[];
  published?: string;
}

export interface FindingComponent {
  purl: string;
  name: string;
  version?: string;
  ecosystem?: string;
  direct: boolean;
}

export interface Finding {
  id: number;
  artifactId: number;
  kind: string;
  title: string;
  message?: string;
  severity: string;
  status: string;
  tools: string[];
  vulnerability: FindingVulnerability | null;
  component: FindingComponent | null;
  fixedVersions: string[];
  reachability: string;
  risk: FindingRisk | null;
  firstSeenRun: number;
  lastSeenRun: number;
  updatedAt: string;
}

export interface FindingsPage {
  findings: Finding[];
  nextCursor: string;
}

export interface FindingsQuery {
  tier?: Tier;
  status?: FindingStatus;
  kind?: string;
  artifact?: number;
  limit?: number;
  cursor?: string;
}

/**
 * Outcome of a read-API call. "disabled" (404 on the listing) means the server runs without
 * AEGISFLOW_DEV_READONLY_API; "unavailable" (503) means no database is configured; "forbidden"
 * (403) means the browser is not a loopback client.
 */
export type ApiOutcome<T> =
  | { state: "ok"; value: T }
  | { state: "disabled" | "unavailable" | "forbidden" | "not-found" | "error"; message: string };

type JSONRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JSONRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

function str(o: JSONRecord, key: string): string | null {
  const v = o[key];
  return typeof v === "string" ? v : null;
}

function num(o: JSONRecord, key: string): number | null {
  const v = o[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function isTier(value: unknown): value is Tier {
  return value === "P1" || value === "P2" || value === "P3";
}

function parseFactor(value: unknown): RiskFactor | null {
  if (!isRecord(value)) return null;
  const name = str(value, "name");
  const kind = str(value, "kind");
  const raw = str(value, "raw");
  const source = str(value, "source");
  const normalized = num(value, "normalized");
  const weight = num(value, "weight");
  const contribution = num(value, "contribution");
  if (name === null || kind === null || raw === null || source === null || normalized === null || weight === null || contribution === null) {
    return null;
  }
  const factor: RiskFactor = { name, kind, raw, normalized, weight, contribution, source };
  const note = str(value, "note");
  if (note) factor.note = note;
  return factor;
}

function parseExplanation(value: unknown): RiskExplanation | null {
  if (!isRecord(value) || !Array.isArray(value["factors"])) return null;
  const factors = value["factors"].map(parseFactor);
  if (factors.some((f) => f === null)) return null;
  return {
    scorer: str(value, "scorer") ?? "",
    score: num(value, "score") ?? 0,
    tier: str(value, "tier") ?? "",
    reason: str(value, "reason") ?? "",
    flags: isStringArray(value["flags"]) ? value["flags"] : [],
    factors: factors as RiskFactor[],
  };
}

function parseRisk(value: unknown): FindingRisk | null | undefined {
  if (value === null) return null;
  if (!isRecord(value)) return undefined;
  const score = num(value, "score");
  const tier = value["tier"];
  if (score === null || !isTier(tier)) return undefined;
  const risk: FindingRisk = {
    score,
    tier,
    action: str(value, "action") ?? "",
    reason: str(value, "reason") ?? "",
    flags: isStringArray(value["flags"]) ? value["flags"] : [],
    scoredAt: str(value, "scoredAt") ?? "",
  };
  if (value["explanation"] !== undefined) {
    const explanation = parseExplanation(value["explanation"]);
    if (explanation) risk.explanation = explanation;
  }
  return risk;
}

function parseVulnerability(value: unknown): FindingVulnerability | null | undefined {
  if (value === null) return null;
  if (!isRecord(value)) return undefined;
  const id = str(value, "id");
  if (id === null || !isStringArray(value["aliases"])) return undefined;
  const v: FindingVulnerability = { id, aliases: value["aliases"], severity: str(value, "severity") ?? "unknown" };
  const summary = str(value, "summary");
  if (summary) v.summary = summary;
  const published = str(value, "published");
  if (published) v.published = published;
  if (isStringArray(value["cwes"])) v.cwes = value["cwes"];
  if (Array.isArray(value["cvss"])) {
    const ratings: CVSSRating[] = [];
    for (const r of value["cvss"]) {
      if (!isRecord(r)) continue;
      const version = str(r, "version");
      const baseScore = num(r, "baseScore");
      if (version === null || baseScore === null) continue;
      const rating: CVSSRating = { version, baseScore };
      const vector = str(r, "vector");
      if (vector) rating.vector = vector;
      ratings.push(rating);
    }
    v.cvss = ratings;
  }
  return v;
}

function parseComponent(value: unknown): FindingComponent | null | undefined {
  if (value === null) return null;
  if (!isRecord(value)) return undefined;
  const purl = str(value, "purl");
  const name = str(value, "name");
  if (purl === null || name === null) return undefined;
  const c: FindingComponent = { purl, name, direct: value["direct"] === true };
  const version = str(value, "version");
  if (version) c.version = version;
  const ecosystem = str(value, "ecosystem");
  if (ecosystem) c.ecosystem = ecosystem;
  return c;
}

/** Validates one finding object; null when the payload does not match the API contract. */
export function parseFinding(value: unknown): Finding | null {
  if (!isRecord(value)) return null;
  const id = num(value, "id");
  const artifactId = num(value, "artifactId");
  const kind = str(value, "kind");
  const title = str(value, "title");
  const severity = str(value, "severity");
  const status = str(value, "status");
  const reachability = str(value, "reachability");
  const risk = parseRisk(value["risk"]);
  const vulnerability = parseVulnerability(value["vulnerability"]);
  const component = parseComponent(value["component"]);
  if (
    id === null ||
    artifactId === null ||
    kind === null ||
    title === null ||
    severity === null ||
    status === null ||
    reachability === null ||
    risk === undefined ||
    vulnerability === undefined ||
    component === undefined ||
    !isStringArray(value["tools"]) ||
    !isStringArray(value["fixedVersions"])
  ) {
    return null;
  }
  const finding: Finding = {
    id,
    artifactId,
    kind,
    title,
    severity,
    status,
    tools: value["tools"],
    vulnerability,
    component,
    fixedVersions: value["fixedVersions"],
    reachability,
    risk,
    firstSeenRun: num(value, "firstSeenRun") ?? 0,
    lastSeenRun: num(value, "lastSeenRun") ?? 0,
    updatedAt: str(value, "updatedAt") ?? "",
  };
  const message = str(value, "message");
  if (message) finding.message = message;
  return finding;
}

/** Validates a listing payload. */
export function parseFindingsPage(value: unknown): FindingsPage | null {
  if (!isRecord(value) || !Array.isArray(value["findings"]) || typeof value["nextCursor"] !== "string") return null;
  const findings = value["findings"].map(parseFinding);
  if (findings.some((f) => f === null)) return null;
  return { findings: findings as Finding[], nextCursor: value["nextCursor"] };
}

/** Builds the listing URL; only known parameters are sent. */
export function findingsURL(query: FindingsQuery = {}): string {
  const params = new URLSearchParams();
  if (query.tier) params.set("tier", query.tier);
  if (query.status) params.set("status", query.status);
  if (query.kind) params.set("kind", query.kind);
  if (query.artifact !== undefined) params.set("artifact", String(query.artifact));
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.cursor) params.set("cursor", query.cursor);
  const qs = params.toString();
  return qs ? `/api/v1/findings?${qs}` : "/api/v1/findings";
}

async function problemDetail(res: Response): Promise<string> {
  try {
    const body: unknown = await res.json();
    if (isRecord(body) && typeof body["detail"] === "string") return body["detail"];
  } catch {
    // not JSON: fall through
  }
  return `HTTP ${res.status}`;
}

async function request<T>(
  url: string,
  parse: (v: unknown) => T | null,
  notFound: "disabled" | "not-found",
  fetcher: Fetcher,
  signal?: AbortSignal,
): Promise<ApiOutcome<T>> {
  const init: RequestInit = { headers: { Accept: "application/json" } };
  if (signal) init.signal = signal;
  let res: Response;
  try {
    res = await fetcher(url, init);
  } catch (err) {
    if (signal?.aborted) throw err;
    return { state: "error", message: err instanceof Error ? err.message : "network error" };
  }
  if (res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      return { state: "error", message: "invalid JSON from the server" };
    }
    const value = parse(body);
    return value === null ? { state: "error", message: "unexpected payload from the server" } : { state: "ok", value };
  }
  const message = await problemDetail(res);
  switch (res.status) {
    case 404:
      return { state: notFound, message };
    case 403:
      return { state: "forbidden", message };
    case 503:
      return { state: "unavailable", message };
    default:
      return { state: "error", message };
  }
}

export function listFindings(query: FindingsQuery, fetcher: Fetcher = defaultFetcher, signal?: AbortSignal) {
  return request(findingsURL(query), parseFindingsPage, "disabled", fetcher, signal);
}

export function getFinding(id: number, fetcher: Fetcher = defaultFetcher, signal?: AbortSignal) {
  if (!Number.isSafeInteger(id) || id <= 0) {
    return Promise.resolve<ApiOutcome<Finding>>({ state: "not-found", message: "invalid finding ID" });
  }
  return request(`/api/v1/findings/${id}`, parseFinding, "not-found", fetcher, signal);
}

// ---------- presentation helpers (pure, unit-tested) ----------

export function formatScore(score: number): string {
  return score.toFixed(score % 1 === 0 ? 0 : 1);
}

const reachabilityLabels: Record<string, string> = {
  called: "Called",
  imported: "Imported",
  unknown: "Unknown",
};

export function reachabilityLabel(value: string): string {
  return reachabilityLabels[value] ?? (value || "—");
}

const statusLabels: Record<string, string> = {
  open: "Open",
  fixed: "Fixed",
  vex_not_affected: "Not affected (VEX)",
  accepted: "Accepted",
};

export function statusLabel(value: string): string {
  return statusLabels[value] ?? value;
}

/** Parses "/vulnerabilities/<id>" (optional trailing slash); null for anything else. */
export function findingIdFromPath(pathname: string): number | null {
  const m = /^\/vulnerabilities\/(\d{1,15})\/?$/.exec(pathname);
  if (!m?.[1]) return null;
  const id = Number(m[1]);
  return id > 0 ? id : null;
}

/** Formats a factor's contribution in points with an explicit sign. */
export function formatContribution(points: number): string {
  if (points === 0) return "0";
  const fixed = Math.abs(points).toFixed(2).replace(/\.?0+$/, "");
  return `${points > 0 ? "+" : "−"}${fixed}`;
}
