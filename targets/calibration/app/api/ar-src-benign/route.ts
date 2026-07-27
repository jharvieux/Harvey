import { exec } from "node:child_process";

const TASKS = new Map<string, string>([["nightly", "vacuumdb"]]);

// SAFE LOOKALIKE (N-SOURCE-BENIGN-GET, #1221): three `.get()`/property reads that are NOT request
// input — a Map lookup, an upstream Response's headers, and that Response's body — each reaching a
// command or log sink. This is exactly the FP shape a free `$REQ.` metavariable produced when the
// source widening was measured: it fired on every one of them. The name-constrained source block
// must stay silent here while every ar-src-* positive still fires.
export async function GET() {
  const upstream = await fetch("https://internal.example.com/manifest");

  const task = TASKS.get("nightly");
  const etag = upstream.headers.get("etag");
  const payload = upstream.body;

  exec(`run ${task}`);
  console.log(`etag ${etag} payload ${payload}`);
  return new Response("ok");
}
