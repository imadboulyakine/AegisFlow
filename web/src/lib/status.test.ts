import { describe, expect, test } from "bun:test";
import type { Fetcher } from "./api";
import {
  deriveState,
  errorMessage,
  formatBuildDate,
  loadStatus,
  shortCommit,
  stateLabel,
  type StatusSnapshot,
} from "./status";

const version = { version: "v0.1.0", commit: "abc1234", buildDate: "", goVersion: "go1.27.3" };

describe("deriveState", () => {
  const cases: [string, StatusSnapshot | null, string][] = [
    ["loading", null, "loading"],
    [
      "operational",
      { readiness: { ok: true, value: { ready: true, status: "ready" } }, version: { ok: true, value: version } },
      "operational",
    ],
    [
      "not ready",
      {
        readiness: { ok: true, value: { ready: false, status: "shutting_down" } },
        version: { ok: true, value: version },
      },
      "degraded",
    ],
    [
      "version failed",
      { readiness: { ok: true, value: { ready: true, status: "ready" } }, version: { ok: false, error: "500" } },
      "degraded",
    ],
    ["both failed", { readiness: { ok: false, error: "x" }, version: { ok: false, error: "y" } }, "unreachable"],
  ];

  test.each(cases)("%s", (_name, snapshot, expected) => {
    expect(deriveState(snapshot)).toBe(expected as ReturnType<typeof deriveState>);
  });

  test("every state has a label", () => {
    for (const state of ["loading", "operational", "degraded", "unreachable"] as const) {
      expect(stateLabel(state).length).toBeGreaterThan(0);
    }
  });
});

describe("shortCommit", () => {
  test.each([
    ["0123456789abcdef0123456789abcdef01234567", "0123456789ab"],
    ["abc1234", "abc1234"],
    ["  ", "unknown"],
    ["unknown", "unknown"],
    ["not-a-sha", "not-a-sha"],
  ])("%p -> %p", (input, expected) => {
    expect(shortCommit(input)).toBe(expected);
  });
});

describe("formatBuildDate", () => {
  test.each([
    ["2026-10-26T12:34:56Z", "2026-10-26 12:34 UTC"],
    ["2026-10-26T14:34:56+02:00", "2026-10-26 12:34 UTC"],
    ["", "unknown"],
    ["unknown", "unknown"],
    ["yesterday", "unknown"],
  ])("%p -> %p", (input, expected) => {
    expect(formatBuildDate(input)).toBe(expected);
  });
});

describe("errorMessage", () => {
  test("handles Error, string and unknown values", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
    expect(errorMessage("plain")).toBe("plain");
    expect(errorMessage(42)).toBe("unknown error");
  });
});

describe("loadStatus", () => {
  test("collects both probes and never rejects", async () => {
    const fetcher: Fetcher = async (url) => {
      if (url === "/readyz") return Response.json({ status: "ready" });
      throw new TypeError("network down");
    };
    const snapshot = await loadStatus(fetcher);
    expect(snapshot.readiness).toEqual({ ok: true, value: { ready: true, status: "ready" } });
    expect(snapshot.version).toEqual({ ok: false, error: "network down" });
    expect(deriveState(snapshot)).toBe("degraded");
  });
});
