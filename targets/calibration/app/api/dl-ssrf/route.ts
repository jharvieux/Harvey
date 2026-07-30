import { downloadRemote } from "../../../lib/dl-fetch";

// PLANTED BUG (P-SSRF-WRAPPER-UNCURATED, #1325 — #570 remainder): the URL is read via the App
// Router query-access idiom and passed to a shared fetch-wrapper named OUTSIDE harvey-ssrf-fetch's
// curated four (fetchRemote/fetchUrl/fetchExternal/proxyFetch) — so the semgrep rule's name-keyed
// sink cannot see this call at all. detectSsrfWrapperFindings resolves the cross-file import and
// checks the wrapper's definition SHAPE instead of its name.
export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get("url") || "";
  const body = await downloadRemote(url);
  return new Response(body);
}
