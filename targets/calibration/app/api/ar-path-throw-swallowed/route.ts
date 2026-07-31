import { readFile } from "node:fs/promises";
import path from "node:path";

const BASE = "/var/data/exports";

// P-PATH-TRAVERSAL-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the containment arm's
// swallowed-throw shape. The prefix test is on the RESOLVED path and the branch leaves the if —
// every #1220 constraint holds — but the guard sits inside a `try` whose `catch` swallows, so
// `../../etc/passwd` reaches readFile with the rejection logged and ignored.
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("doc") ?? "";
  const resolved = path.resolve(BASE, name);
  try {
    if (!resolved.startsWith(`${BASE}/`)) throw new Error("forbidden");
  } catch (err) {
    console.warn("path rejected");
  }

  return new Response(await readFile(resolved));
}
