// Test cases for ts-react-html-injection (run: make sast-test).
import { createElement } from "react";

export function SafeSummary({ summary }: { summary: string }) {
  // ok: ts-react-html-injection
  return <p className="summary">{summary}</p>;
}

export function UnsafeSummary({ summary }: { summary: string }) {
  // ruleid: ts-react-html-injection
  return <p dangerouslySetInnerHTML={{ __html: summary }} />;
}

export function UnsafeWithChildren({ html }: { html: string }) {
  // ruleid: ts-react-html-injection
  return <div dangerouslySetInnerHTML={{ __html: html }}></div>;
}

export function unsafeCreateElement(html: string) {
  // ruleid: ts-react-html-injection
  return createElement("div", { dangerouslySetInnerHTML: { __html: html } });
}

export function domSinks(node: HTMLElement, text: string) {
  // ok: ts-react-html-injection
  node.textContent = text;
  // ruleid: ts-react-html-injection
  node.innerHTML = text;
  // ruleid: ts-react-html-injection
  node.insertAdjacentHTML("beforeend", text);
  // ruleid: ts-react-html-injection
  document.write(text);
}
