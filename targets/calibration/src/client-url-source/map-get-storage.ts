// #1708 NEGATIVE (N-CLIENT-URL-MAP-GET). A Map row-bag built from a database read inside a cron
// job, whose "path" entry is a stored object key. This pairs the third receiver base.yml's block
// names (a plain Map) with the third sink #1708 widened, the Supabase Storage object key. The key
// comes off a row the job itself selected — the shape N-STORAGE-DB-PATH already charges for on the
// request side — so no source in this module is attacker-controlled under any reading. The key is
// assembled under a tenant prefix because without one the storage-tenant-scope AST detector (#1198)
// correctly reports it, and a negative has to be benign to EVERY detector, not just the one it
// exists to charge — the calibration gate scored that and failed on it before this line existed.
declare const serviceClient: {
  storage: { from(bucket: string): { download(path: string): Promise<unknown> } };
};

export async function archiveExport(tenantId: string, row: Map<string, string>) {
  const relativeKey = row.get("path");
  return serviceClient.storage.from("private").download(`${tenantId}/exports/${relativeKey}`);
}
