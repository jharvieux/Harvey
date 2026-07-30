// Shared thin fetch-wrapper used by the cross-file SSRF fixtures (#1325, #570 remainder). Named
// deliberately UNLIKE harvey-ssrf-fetch's curated four (fetchRemote/fetchUrl/fetchExternal/
// proxyFetch) — the whole point of this fixture is a wrapper name outside that list, which the
// semgrep rule cannot see and detectSsrfWrapperFindings (src/scan/ssrf-wrapper.ts) must catch by
// SHAPE instead. `target` here is a plain parameter, not a request source, so this helper is not
// itself flagged.
export async function downloadRemote(target: string): Promise<string> {
  const res = await fetch(target, { redirect: "follow" });
  return await res.text();
}
