import fs from "node:fs";
import path from "node:path";

// PLANTED BUG (P-PATH-SEARCHPARAMS, #1220/#1221): the file name is read via the inline
// `new URL(request.url).searchParams.get(...)` form and joined into a read path. This is the exact
// probe #1220 measured silent while its `req.query` control fired — two independent causes, the
// source vocabulary being the first.
export async function GET(request: Request) {
  const name = new URL(request.url).searchParams.get("path") ?? "";
  return new Response(fs.readFileSync(path.join("/var/data/uploads", name)));
}
