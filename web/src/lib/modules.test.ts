import { describe, expect, test } from "bun:test";
import { findModule, modules } from "./modules";

describe("modules", () => {
  test("ids and paths are unique", () => {
    expect(new Set(modules.map((m) => m.id)).size).toBe(modules.length);
    expect(new Set(modules.map((m) => m.path)).size).toBe(modules.length);
  });

  test("only Vulnerabilities is available in Phase 2", () => {
    expect(modules.map((m) => m.title)).toEqual(["Supply Chain", "Vulnerabilities", "Policies", "Anomalies"]);
    expect(modules.filter((m) => m.status === "available").map((m) => m.id)).toEqual(["vulnerabilities"]);
  });
});

describe("findModule", () => {
  test.each([
    ["/vulnerabilities", "vulnerabilities"],
    ["/vulnerabilities/", "vulnerabilities"],
    ["/supply-chain", "supply-chain"],
    ["/", undefined],
    ["/unknown", undefined],
    ["/vulnerabilities/123", undefined],
  ])("%p -> %p", (path, expected) => {
    expect(findModule(path)?.id).toBe(expected as string);
  });
});
