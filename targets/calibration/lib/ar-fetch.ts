// Shared thin fetch-wrapper used by the App Router SSRF fixtures (#570). The fetch() sink lives here,
// cross-file from the request source in the route handler — which is exactly why harvey-ssrf-fetch
// also keys its sink on the wrapper-CALL name (OSS Semgrep taint is single-file, so the tainted URL
// and the raw fetch() never share a file). `url` here is a plain parameter, not a request source, so
// this helper is not itself flagged.
export async function fetchRemote(url: string): Promise<string> {
  const res = await fetch(url, { redirect: "follow" });
  return await res.text();
}
