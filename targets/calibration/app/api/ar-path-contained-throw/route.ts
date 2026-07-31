import { readFile } from "node:fs/promises";
import path from "node:path";

const BASE = "/var/data/exports";

// N-PATH-RESOLVE-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-PATH-RESOLVE-VERIFIED — the same resolve-then-re-verify containment, rejecting by throw. In an
// App Router handler under an error boundary this is the ordinary spelling; before #1248 it read
// as a path traversal.
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("doc") ?? "";
  const resolved = path.resolve(BASE, name);
  if (!resolved.startsWith(`${BASE}/`)) throw new Error("forbidden");

  return new Response(await readFile(resolved));
}
