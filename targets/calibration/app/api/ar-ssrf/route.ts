import { fetchRemote } from "../../../lib/ar-fetch";

// PLANTED BUG (P-SSRF-APPROUTER, #570): the URL is read via new URL(req.url).searchParams.get("url")
// (the App Router query-access idiom) and passed to a shared fetch-wrapper with no host allowlist —
// SSRF. The Express-only sources missed the searchParams shape, and the raw fetch() sink lives
// cross-file in the helper, so the sink also keys on the wrapper call. harvey-ssrf-fetch → review.
export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get("url") || "";
  const body = await fetchRemote(url);
  return new Response(body);
}
