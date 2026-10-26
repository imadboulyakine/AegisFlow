// A deliberately tiny History-API router: enough for a handful of client routes
// without pulling a routing library into the supply chain. The Go server falls
// back to index.html for unknown non-API paths, so deep links work.
import { useSyncExternalStore } from "react";

const listeners = new Set<() => void>();

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  window.addEventListener("popstate", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("popstate", listener);
  };
}

function getPathname(): string {
  return window.location.pathname;
}

export function navigate(path: string): void {
  if (path === window.location.pathname) return;
  window.history.pushState(null, "", path);
  for (const listener of listeners) listener();
}

/** Current pathname; `serverPath` is used during server-side rendering (tests). */
export function usePathname(serverPath = "/"): string {
  return useSyncExternalStore(subscribe, getPathname, () => serverPath);
}

/** True for plain left-clicks that the router should handle instead of the browser. */
export function isPlainLeftClick(event: {
  button: number;
  metaKey: boolean;
  altKey: boolean;
  ctrlKey: boolean;
  shiftKey: boolean;
  defaultPrevented: boolean;
}): boolean {
  return (
    !event.defaultPrevented &&
    event.button === 0 &&
    !event.metaKey &&
    !event.altKey &&
    !event.ctrlKey &&
    !event.shiftKey
  );
}
