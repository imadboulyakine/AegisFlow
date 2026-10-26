import { describe, expect, test } from "bun:test";
import { ApiError, getReadiness, getVersion, isVersionInfo, type Fetcher } from "./api";

const versionPayload = {
  version: "v0.1.0",
  commit: "0123456789abcdef0123456789abcdef01234567",
  buildDate: "2026-10-26T12:00:00Z",
  goVersion: "go1.27.3",
};

function respond(status: number, body: unknown): Fetcher {
  return async () =>
    new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
}

describe("isVersionInfo", () => {
  test.each([
    [versionPayload, true],
    [{ ...versionPayload, commit: 42 }, false],
    [{ version: "v1" }, false],
    [null, false],
    [[], false],
    ["v1", false],
  ])("%p -> %p", (input, expected) => {
    expect(isVersionInfo(input)).toBe(expected);
  });
});

describe("getVersion", () => {
  test("requests the versioned API with an Accept header", async () => {
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    const fetcher: Fetcher = async (url, init) => {
      calls.push({ url, init });
      return Response.json(versionPayload);
    };
    const controller = new AbortController();

    await expect(getVersion(fetcher, controller.signal)).resolves.toEqual(versionPayload);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("/api/v1/version");
    expect(new Headers(calls[0]?.init?.headers).get("accept")).toBe("application/json");
    expect(calls[0]?.init?.signal).toBe(controller.signal);
  });

  test("rejects non-2xx responses with ApiError", async () => {
    const err = await getVersion(respond(500, { title: "boom" })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(500);
  });

  test("rejects payloads with the wrong shape", async () => {
    await expect(getVersion(respond(200, { version: 1 }))).rejects.toThrow("unexpected version payload");
  });

  test("rejects invalid JSON", async () => {
    await expect(getVersion(respond(200, "<html>"))).rejects.toThrow("invalid JSON");
  });

  test("propagates transport errors", async () => {
    const fetcher: Fetcher = async () => {
      throw new TypeError("Failed to fetch");
    };
    await expect(getVersion(fetcher)).rejects.toThrow("Failed to fetch");
  });
});

describe("getReadiness", () => {
  test("200 means ready", async () => {
    await expect(getReadiness(respond(200, { status: "ready" }))).resolves.toEqual({ ready: true, status: "ready" });
  });

  test("503 means not ready rather than an error", async () => {
    await expect(getReadiness(respond(503, { status: "shutting_down" }))).resolves.toEqual({
      ready: false,
      status: "shutting_down",
    });
  });

  test("missing status field degrades to unknown", async () => {
    await expect(getReadiness(respond(200, {}))).resolves.toEqual({ ready: true, status: "unknown" });
  });

  test("unexpected status codes reject", async () => {
    await expect(getReadiness(respond(404, { title: "Not Found" }))).rejects.toBeInstanceOf(ApiError);
  });
});
