import path from "node:path";
import { admin } from "../../../lib/supabaseAdmin";
import { session } from "../../../lib/auth";

// SAFE LOOKALIKE (N-STORAGE-BASENAME, #1220): same storage sink, but path.basename strips every
// directory component before the key is assembled, so the tenant prefix cannot be escaped. Proves
// the new storage sinks stay taint-gated and honour the existing sanitizer set rather than firing
// on every .storage.from(...) call.
export async function GET(req: Request) {
  const { tenantId } = await session(req);
  const name = path.basename(new URL(req.url).searchParams.get("path") ?? "");

  const { data } = await admin.storage.from("imported-documents").createSignedUrl(`${tenantId}/${name}`, 300);
  return Response.json(data);
}
