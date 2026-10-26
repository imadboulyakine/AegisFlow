import { describe, expect, test } from "bun:test";
import { findModule, modules } from "./modules";

describe("modules", () => {
  test("ids and paths are unique", () => {
    expect(new Set(modules.map((m) => m.id)).size).toBe(modules.length);
    expect(new Set(modules.map((m) => m.path)).size).toBe(modules.length);
  });

  test("all Phase 0 modules are planned placeholders", () => {
    expect(modules.map((m) => m.title)).toEqual(["Supply Chain", "Vulnerabilities", "Policies", "Anomalies"]);
    expect(modules.every((m) => m.status === "planned")).toBe(true);
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
