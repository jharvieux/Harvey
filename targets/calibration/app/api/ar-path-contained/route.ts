import { readFile } from "node:fs/promises";
import path from "node:path";

const BASE = "/var/data/exports";

// SAFE LOOKALIKE (N-PATH-RESOLVE-VERIFIED, #1220): resolve-then-re-verify — the correct containment
// idiom, and the shape that widening the sink set to fs/promises newly reaches. The prefix test is
// on the RESOLVED path, which is what makes it sound and what separates it from ar-storage-path's
// prefix test on the RAW value: path.resolve collapses `..`, so the string it returns IS the path
// the filesystem will open.
//
// Paired deliberately with ar-storage-path, which wears a prefix test that looks almost identical
// and must keep firing. A containment sanitizer that cannot tell them apart is worse than none.
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("doc") ?? "";
  const resolved = path.resolve(BASE, name);
  if (!resolved.startsWith(`${BASE}/`)) return Response.json({ error: "forbidden" }, { status: 403 });

  return new Response(await readFile(resolved));
}
