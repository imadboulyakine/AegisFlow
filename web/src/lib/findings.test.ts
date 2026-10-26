import { describe, expect, test } from "bun:test";
import type { Fetcher } from "./api";
import {
  findingIdFromPath,
  findingsURL,
  formatContribution,
  formatScore,
  getFinding,
  listFindings,
  parseFinding,
  parseFindingsPage,
  reachabilityLabel,
  statusLabel,
} from "./findings";
import { sampleExplanation, sampleFinding } from "./findings.fixtures";

function respond(status: number, body: unknown): Fetcher {
  return async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
}

describe("parseFinding", () => {
  test("accepts the API shape", () => {
    const f = parseFinding(sampleFinding);
    expect(f?.risk?.tier).toBe("P1");
    expect(f?.component?.direct).toBe(true);
    expect(f?.vulnerability?.aliases).toEqual(["GO-2022-1059"]);
  });

  test("accepts unscored findings without vulnerability or component", () => {
    const f = parseFinding({ ...sampleFinding, risk: null, vulnerability: null, component: null, message: "m" });
    expect(f?.risk).toBeNull();
    expect(f?.message).toBe("m");
  });

  test("parses the detail extras", () => {
    const f = parseFinding({
      ...sampleFinding,
      vulnerability: {
        ...sampleFinding.vulnerability,
        summary: "s",
        published: "2022-10-14T00:00:00Z",
        cwes: ["CWE-772"],
        cvss: [{ version: "3.1", vector: "CVSS:3.1/AV:N", baseScore: 7.5 }, { bogus: true }],
      },
      component: { ...sampleFinding.component, ecosystem: "golang" },
      risk: { ...sampleFinding.risk, explanation: sampleExplanation },
    });
    expect(f?.vulnerability?.cvss).toEqual([{ version: "3.1", vector: "CVSS:3.1/AV:N", baseScore: 7.5 }]);
    expect(f?.risk?.explanation?.factors[1]?.note).toBe("symbol called");
    expect(f?.component?.ecosystem).toBe("golang");
  });

  test("drops a malformed explanation but keeps the finding", () => {
    const f = parseFinding({ ...sampleFinding, risk: { ...sampleFinding.risk, explanation: { factors: [{ name: 1 }] } } });
    expect(f).not.toBeNull();
    expect(f?.risk?.explanation).toBeUndefined();
  });

  test.each([
    ["not an object", "x"],
    ["missing id", { ...sampleFinding, id: "7" }],
    ["bad tier", { ...sampleFinding, risk: { ...sampleFinding.risk, tier: "P0" } }],
    ["risk not object", { ...sampleFinding, risk: 5 }],
    ["tools not strings", { ...sampleFinding, tools: [1] }],
    ["bad vulnerability", { ...sampleFinding, vulnerability: { id: 5 } }],
    ["vulnerability not object", { ...sampleFinding, vulnerability: "CVE" }],
    ["bad component", { ...sampleFinding, component: { purl: "x" } }],
    ["component not object", { ...sampleFinding, component: [] }],
    ["no fixedVersions", { ...sampleFinding, fixedVersions: undefined }],
    ["NaN score", { ...sampleFinding, risk: { ...sampleFinding.risk, score: Number.NaN } }],
  ])("rejects %s", (_name, value) => {
    expect(parseFinding(value)).toBeNull();
  });

  test("page validation", () => {
    expect(parseFindingsPage({ findings: [sampleFinding], nextCursor: "" })?.findings).toHaveLength(1);
    expect(parseFindingsPage({ findings: [{}], nextCursor: "" })).toBeNull();
    expect(parseFindingsPage({ findings: [] })).toBeNull();
    expect(parseFindingsPage(null)).toBeNull();
  });
});

describe("findingsURL", () => {
  test("encodes known parameters only", () => {
    expect(findingsURL()).toBe("/api/v1/findings");
    expect(findingsURL({ tier: "P1", status: "open", kind: "vulnerability", artifact: 3, limit: 50, cursor: "a+b/=" })).toBe(
      "/api/v1/findings?tier=P1&status=open&kind=vulnerability&artifact=3&limit=50&cursor=a%2Bb%2F%3D",
    );
  });
});

describe("listFindings / getFinding", () => {
  test("ok", async () => {
    let seen = "";
    const fetcher: Fetcher = async (input) => {
      seen = input;
      return new Response(JSON.stringify({ findings: [sampleFinding], nextCursor: "n" }), { status: 200 });
    };
    const out = await listFindings({ tier: "P2" }, fetcher);
    expect(seen).toBe("/api/v1/findings?tier=P2");
    expect(out.state).toBe("ok");
    if (out.state === "ok") expect(out.value.nextCursor).toBe("n");
  });

  test.each([
    [404, "disabled"],
    [403, "forbidden"],
    [503, "unavailable"],
    [500, "error"],
  ])("HTTP %p maps to %p", async (status, state) => {
    const out = await listFindings({}, respond(status, { detail: "server detail" }));
    expect(out.state).toBe(state as never);
    if (out.state !== "ok") expect(out.message).toBe("server detail");
  });

  test("non-JSON error bodies and payload errors", async () => {
    const out = await listFindings({}, respond(502, "<html>"));
    expect(out).toEqual({ state: "error", message: "HTTP 502" });
    expect((await listFindings({}, respond(200, "nope"))).state).toBe("error");
    expect((await listFindings({}, respond(200, { findings: "x" }))).state).toBe("error");
  });

  test("network failure", async () => {
    const out = await listFindings({}, async () => {
      throw new Error("offline");
    });
    expect(out).toEqual({ state: "error", message: "offline" });
  });

  test("abort propagates", async () => {
    const controller = new AbortController();
    controller.abort();
    const fetcher: Fetcher = async () => {
      throw new DOMException("aborted", "AbortError");
    };
    expect(listFindings({}, fetcher, controller.signal)).rejects.toThrow();
  });

  test("detail", async () => {
    const ok = await getFinding(7, respond(200, sampleFinding));
    expect(ok.state).toBe("ok");
    expect((await getFinding(7, respond(404, { detail: "No finding matches this ID." }))).state).toBe("not-found");
    expect((await getFinding(0, respond(200, sampleFinding))).state).toBe("not-found");
    expect((await getFinding(1.5, respond(200, sampleFinding))).state).toBe("not-found");
  });
});

describe("presentation helpers", () => {
  test("formatScore", () => {
    expect(formatScore(76)).toBe("76");
    expect(formatScore(28.49)).toBe("28.5");
    expect(formatScore(0)).toBe("0");
  });

  test("labels", () => {
    expect(reachabilityLabel("called")).toBe("Called");
    expect(reachabilityLabel("")).toBe("—");
    expect(reachabilityLabel("weird")).toBe("weird");
    expect(statusLabel("vex_not_affected")).toBe("Not affected (VEX)");
    expect(statusLabel("other")).toBe("other");
  });

  test.each([
    ["/vulnerabilities/42", 42],
    ["/vulnerabilities/42/", 42],
    ["/vulnerabilities/0", null],
    ["/vulnerabilities/abc", null],
    ["/vulnerabilities", null],
    ["/vulnerabilities/1234567890123456", null],
  ])("findingIdFromPath(%p) = %p", (path, id) => {
    expect(findingIdFromPath(path)).toBe(id);
  });

  test("formatContribution", () => {
    expect(formatContribution(30)).toBe("+30");
    expect(formatContribution(-22.8)).toBe("−22.8");
    expect(formatContribution(0)).toBe("0");
    expect(formatContribution(12.345)).toBe("+12.35");
  });
});
