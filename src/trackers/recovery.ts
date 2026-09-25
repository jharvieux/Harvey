import type { CreatedRef } from "./types.js";
import { trackerFetch } from "./http.js";

// Preserve a successful remote creation even when a later operation fails.
export class PartialTrackerWriteError extends Error {
  constructor(readonly ref: CreatedRef, readonly stage: string, cause: unknown) {
    super(`${stage} failed after ticket ${ref.id} was created: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "PartialTrackerWriteError";
  }
}

// Restrict continuation URLs to the original endpoint to keep caller credentials
// inside the scope authorized for the first request.
export function trackerNextLink(response: Response, currentUrl: string): string | undefined {
  const header = response.headers.get("link");
  if (!header) return undefined;
  const next = header.split(/,(?=\s*<)/).filter(part => {
    const relation = part.match(/;\s*rel\s*=\s*(?:"([^"]+)"|([^;\s,]+))/i);
    if (!/^\s*<[^>]+>/.test(part) || !relation) throw new Error("Tracker pagination has a malformed link header");
    return (relation[1] ?? relation[2]!).split(/\s+/).includes("next");
  });
  if (next.length > 1) throw new Error("Tracker pagination has multiple next links");
  if (!next.length) return undefined;
  const target = next[0]!.match(/^\s*<([^>]+)>/);
  if (!target) throw new Error("Tracker pagination has a malformed next link");
  const url = new URL(target[1]!, currentUrl);
  const current = new URL(currentUrl);
  if (url.origin !== current.origin || url.pathname !== current.pathname || url.username || url.password || url.hash) throw new Error("Tracker pagination next link changes endpoint scope");
  const scope = (value: URL): string => { const params = new URLSearchParams(value.search); params.delete("page"); params.delete("per_page"); params.sort(); return params.toString(); };
  if (scope(url) !== scope(current)) throw new Error("Tracker pagination next link changes query scope");
  if (url.href === current.href) throw new Error("Tracker pagination repeats its current page");
  return url.href;
}

export async function* trackerRecoveryPages<T>(fetchImpl: typeof fetch, initialUrl: string, headers: Record<string, string>): AsyncGenerator<T[]> {
  let url = initialUrl;
  const seen = new Set<string>();
  for (let page = 0; page < 100; page++) {
    if (seen.has(url)) throw new Error("Tracker recovery pagination repeats a page");
    seen.add(url);
    const response = await trackerFetch(fetchImpl, url, { method: "GET", headers });
    const rows: unknown = await response.json();
    if (!Array.isArray(rows)) throw new Error("Tracker recovery returned a malformed page");
    const next = trackerNextLink(response, url);
    const nextPage = response.headers.get("x-next-page");
    let numberedNext: string | undefined;
    if (nextPage) {
      if (!/^[1-9]\d*$/.test(nextPage) || !Number.isSafeInteger(Number(nextPage))) throw new Error("Tracker recovery has an invalid next-page header");
      const numbered = new URL(url); numbered.searchParams.set("page", nextPage); numberedNext = numbered.href;
      if (next && new URL(next).searchParams.get("page") !== nextPage) throw new Error("Tracker recovery has contradictory continuation headers");
    } else if (nextPage === "" && next) throw new Error("Tracker recovery has contradictory continuation headers");
    yield rows as T[];
    if (next) { url = next; continue; }
    if (numberedNext) { url = numberedNext; continue; }
    if (nextPage === "") return;
    if (rows.length < 100) return;
    const fallback = new URL(url);
    const currentPage = Number(fallback.searchParams.get("page"));
    if (!Number.isSafeInteger(currentPage) || currentPage < 1) throw new Error("Tracker recovery has no valid continuation");
    fallback.searchParams.set("page", String(currentPage + 1));
    url = fallback.href;
  }
  throw new Error("Tracker recovery incomplete: pagination limit");
}

export function assertTrackerRef(ref: CreatedRef): CreatedRef {
  let validUrl = false;
  try { const url = new URL(ref.url); validUrl = ["http:", "https:"].includes(url.protocol) && !url.username && !url.password; } catch { /* A missing or malformed link cannot identify the created ticket. */ }
  if (typeof ref.id !== "string" || !ref.id.trim() || ["undefined", "null", "NaN"].includes(ref.id)
    || !validUrl) throw new Error("Tracker creation returned an invalid reference; completed state is unknown");
  return ref;
}
