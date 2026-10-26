import { describe, expect, test } from "bun:test";
import { findCspViolations, findCssViolations } from "./build";

describe("findCspViolations", () => {
  test("accepts external module scripts and stylesheets", () => {
    const html = `<!doctype html><html><head>
      <link rel="stylesheet" crossorigin href="/assets/index-abc.css">
      <script type="module" crossorigin src="/assets/index-abc.js"></script>
      </head><body><div id="root"></div></body></html>`;
    expect(findCspViolations(html)).toEqual([]);
  });

  test.each([
    ["<script>alert(1)</script>", "inline <script> element"],
    ['<script type="module">import "/x.js"</script>', "inline <script> element"],
    ["<style>body{}</style>", "inline <style> element"],
    ['<div style="color:red"></div>', "style attribute"],
    ['<img src="/a.png" onerror="x()">', "inline event handler attribute"],
    ['<a href="javascript:void(0)">x</a>', "javascript: URL"],
  ])("rejects %p", (html, problem) => {
    expect(findCspViolations(html)).toContain(problem);
  });
});

describe("findCssViolations", () => {
  test("flags inlined data: URIs", () => {
    expect(findCssViolations(".a{background:url(data:image/svg+xml;base64,AAAA)}")).toHaveLength(1);
    expect(findCssViolations('.a{background:url( "data:image/png;base64,AAAA")}')).toHaveLength(1);
  });

  test("accepts same-origin URLs", () => {
    expect(findCssViolations(".a{background:url(/assets/logo-abc.svg)}")).toEqual([]);
  });
});
