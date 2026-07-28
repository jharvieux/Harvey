import { supabase } from "../db/supabase";

// #1198/#1344 NEGATIVE — the object key comes OUT OF A ROW, not off the request.
//
// The caller supplies only a row id. The row is fetched through a query it must already be
// entitled to satisfy, and `job.storage_path` is whatever that row says — the request never gets
// to name a path. This is the SAFEST real-world spelling of a scoped download, and
// storage-tenant-scope.ts scored it identically to the unguarded one, because it judged the path by
// NAME and a DB-derived path never contains the words "tenant"/"session"/"org".
//
// MEASURED 2026-07-27: fired High (review tier) before #1344. Two detectors then disagreed about
// one route — harvey-path-traversal was deliberately taught to stay silent on exactly this shape
// (#1220, N-STORAGE-DB-PATH) while this one reported it.
//
// The scope control is storage-path-no-tenant.ts in the same directory: `downloadAttachment` takes
// the object key straight off the request and MUST keep firing. If this file goes silent because
// the whole download sink was dropped, that one fails.
export async function downloadExport(jobId: string) {
  const { data: job } = await supabase.from("export_jobs").select("storage_path").eq("id", jobId).single();
  if (!job?.storage_path) return null;
  const { data } = await supabase.storage.from("exports").download(job.storage_path);
  return data;
}
