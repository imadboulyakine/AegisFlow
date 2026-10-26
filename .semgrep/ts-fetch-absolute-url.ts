// Test cases for ts-fetch-absolute-url (run: make sast-test).
type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

export async function sameOrigin(fetcher: Fetcher): Promise<Response> {
  // ok: ts-fetch-absolute-url
  await fetch("/api/v1/version", { headers: { Accept: "application/json" } });
  // ok: ts-fetch-absolute-url
  return fetcher("/readyz");
}

export async function crossOrigin(data: string): Promise<void> {
  // ruleid: ts-fetch-absolute-url
  await fetch("https://collector.example.invalid/ingest", { method: "POST", body: data });
  // ruleid: ts-fetch-absolute-url
  await globalThis.fetch("http://127.0.0.1:9999/x");
  // ruleid: ts-fetch-absolute-url
  navigator.sendBeacon("//collector.example.invalid/b", data);
  // ruleid: ts-fetch-absolute-url
  new WebSocket("wss://collector.example.invalid/ws");
}
