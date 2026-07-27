import { readFile } from "node:fs/promises";
import { join } from "node:path";

// PLANTED BUG (P-PATH-FS-PROMISES, #1220): the idiomatic App Router file read —
// `import { readFile } from "node:fs/promises"` called BARE. All five modelled path sinks were
// spelled with a literal `fs.` prefix and were callback/sync forms, so the promise API reached
// none of them however the value arrived.
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("doc") ?? "";
  return new Response(await readFile(join("/var/data/exports", name)));
}
