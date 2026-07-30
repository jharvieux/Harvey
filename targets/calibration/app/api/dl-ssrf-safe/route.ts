import { downloadRemote } from "../../../lib/dl-fetch";

// TRUE NEGATIVE (N-SSRF-WRAPPER-UNCURATED-FIXED, #1325 — #570 remainder): the fetch-wrapper is
// called with a fixed, non-request URL — no request-tainted value reaches the sink, so
// detectSsrfWrapperFindings never fires. Cleared.
export async function GET() {
  const body = await downloadRemote("https://cdn.example.com/logo.png");
  return new Response(body);
}
