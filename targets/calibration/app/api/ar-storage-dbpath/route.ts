import { tenantClient } from "../../../lib/tenant-client";
import { session } from "../../../lib/auth";

// SAFE LOOKALIKE (N-STORAGE-DB-PATH, #1220): the storage key is read from a DB row through a
// TENANT-SCOPED client — the request only supplies the row id. This is the second ATC route the
// external tool flagged and Harvey correctly did not: a fix that lights this up has bought its
// storage-sink recall with precision, so the entry exists to charge for that.
export async function GET(req: Request, { params }: { params: { jobId: string } }) {
  const { ctx } = await session(req);
  const db = tenantClient(ctx);

  const { data: row } = await db.from("help_doc_versions").select("storage_path").eq("id", params.jobId).maybeSingle();
  if (!row?.storage_path) return Response.json({ state: "pending" });

  const { data: signed } = await db.storage.from("help-docs").createSignedUrl(row.storage_path, 3600);
  return Response.json({ state: "ready", signed_url: signed?.signedUrl });
}
