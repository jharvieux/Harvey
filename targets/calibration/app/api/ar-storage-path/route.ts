import { admin } from "../../../lib/supabaseAdmin";
import { session } from "../../../lib/auth";

// PLANTED BUG (P-STORAGE-TRAVERSAL, #1220): a request-controlled object key reaches Supabase
// Storage on a SERVICE-ROLE client, guarded only by a tenant-id PREFIX check. This is the real ATC
// shape an external SAST tool flagged and Harvey reported nothing for — storage was an unmodeled
// path-sink surface entirely.
//
// The guard is the point: `startsWith(<tenant>/)` is a PREFIX test, not a CONTAINMENT test, and
// `<tenant>/../<other-tenant>/secret.pdf` satisfies it (jharvieux/ATC#2050). This entry is what
// stops a future sanitizer widening from quietly accepting a prefix check as sufficient —
// it must keep firing.
export async function GET(req: Request) {
  const { tenantId } = await session(req);
  const key = new URL(req.url).searchParams.get("path") ?? "";
  if (!key.startsWith(`${tenantId}/`)) return Response.json({ error: "forbidden" }, { status: 403 });

  const { data } = await admin.storage.from("imported-documents").createSignedUrl(key, 300);
  return Response.json(data);
}
