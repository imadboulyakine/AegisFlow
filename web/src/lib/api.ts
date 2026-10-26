// Minimal, dependency-free client for the AegisFlow Go API.
// All requests are same-origin (the SPA is served by the Go binary), which keeps
// the strict CSP (`default-src 'self'`) intact without any connect-src exceptions.

/** Build metadata returned by `GET /api/v1/version`. */
export interface VersionInfo {
  version: string;
  commit: string;
  buildDate: string;
  goVersion: string;
}

/** Result of probing `GET /readyz`. */
export interface Readiness {
  ready: boolean;
  status: string;
}

/** The subset of `fetch` the client needs; injectable for tests. */
export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const jsonHeaders = { Accept: "application/json" } as const;

/** Calls the global fetch lazily so tests can stub it and `this` is never rebound. */
export const defaultFetcher: Fetcher = (input, init) => globalThis.fetch(input, init);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Runtime guard: never trust the shape of a network response. */
export function isVersionInfo(value: unknown): value is VersionInfo {
  return (
    isRecord(value) &&
    typeof value["version"] === "string" &&
    typeof value["commit"] === "string" &&
    typeof value["buildDate"] === "string" &&
    typeof value["goVersion"] === "string"
  );
}

async function readJSON(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    throw new ApiError(`invalid JSON from ${res.url || "server"}`, res.status);
  }
}

export async function getVersion(fetcher: Fetcher = defaultFetcher, signal?: AbortSignal): Promise<VersionInfo> {
  const init: RequestInit = { headers: jsonHeaders };
  if (signal) init.signal = signal;
  const res = await fetcher("/api/v1/version", init);
  if (!res.ok) {
    throw new ApiError(`version request failed with HTTP ${res.status}`, res.status);
  }
  const body = await readJSON(res);
  if (!isVersionInfo(body)) {
    throw new ApiError("unexpected version payload", res.status);
  }
  return body;
}

/**
 * Probes readiness. A 503 is a valid answer ("not ready"), not an error;
 * only transport failures and unexpected statuses reject.
 */
export async function getReadiness(fetcher: Fetcher = defaultFetcher, signal?: AbortSignal): Promise<Readiness> {
  const init: RequestInit = { headers: jsonHeaders };
  if (signal) init.signal = signal;
  const res = await fetcher("/readyz", init);
  if (res.status !== 200 && res.status !== 503) {
    throw new ApiError(`readiness probe returned HTTP ${res.status}`, res.status);
  }
  const body = await readJSON(res);
  const status = isRecord(body) && typeof body["status"] === "string" ? body["status"] : "unknown";
  return { ready: res.status === 200, status };
}

