// Pure presentation helpers for the status card (unit-tested, no DOM access).
import { defaultFetcher, getReadiness, getVersion, type Fetcher, type Readiness, type VersionInfo } from "./api";

export type ServiceState = "loading" | "operational" | "degraded" | "unreachable";

export type Outcome<T> = { ok: true; value: T } | { ok: false; error: string };

export interface StatusSnapshot {
  readiness: Outcome<Readiness>;
  version: Outcome<VersionInfo>;
}

/** Collapses the two probes into a single, user-facing service state. */
export function deriveState(snapshot: StatusSnapshot | null): ServiceState {
  if (snapshot === null) return "loading";
  const { readiness, version } = snapshot;
  if (!readiness.ok && !version.ok) return "unreachable";
  if (readiness.ok && readiness.value.ready && version.ok) return "operational";
  return "degraded";
}

const labels: Record<ServiceState, string> = {
  loading: "Checking…",
  operational: "Operational",
  degraded: "Degraded",
  unreachable: "Unreachable",
};

export function stateLabel(state: ServiceState): string {
  return labels[state];
}

/** Shortens a git SHA for display; empty or placeholder values become "unknown". */
export function shortCommit(commit: string, length = 12): string {
  const trimmed = commit.trim();
  if (trimmed === "" || trimmed === "unknown") return "unknown";
  return /^[0-9a-f]{7,64}$/i.test(trimmed) ? trimmed.slice(0, length) : trimmed;
}

/** Formats an RFC 3339 build timestamp in UTC; invalid or empty input becomes "unknown". */
export function formatBuildDate(value: string): string {
  if (value.trim() === "" || value === "unknown") return "unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown";
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return typeof err === "string" ? err : "unknown error";
}

async function settle<T>(promise: Promise<T>): Promise<Outcome<T>> {
  try {
    return { ok: true, value: await promise };
  } catch (err) {
    return { ok: false, error: errorMessage(err) };
  }
}

/** Runs both probes concurrently; never rejects, each probe reports its own outcome. */
export async function loadStatus(fetcher: Fetcher = defaultFetcher, signal?: AbortSignal): Promise<StatusSnapshot> {
  const [readiness, version] = await Promise.all([
    settle(getReadiness(fetcher, signal)),
    settle(getVersion(fetcher, signal)),
  ]);
  return { readiness, version };
}
