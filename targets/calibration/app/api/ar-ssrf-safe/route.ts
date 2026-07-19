import { fetchRemote } from "../../../lib/ar-fetch";

// TRUE NEGATIVE (N-SSRF-APPROUTER-FIXED, #570): the fetch-wrapper is called with a fixed, non-request
// URL — no request-tainted value reaches the sink, so harvey-ssrf-fetch's taint flow never connects.
// Cleared. Regression guard for the new searchParams / await-req.json() sources and the wrapper sink.
export async function GET() {
  const body = await fetchRemote("https://cdn.example.com/logo.png");
  return new Response(body);
}
