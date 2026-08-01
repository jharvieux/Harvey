// #1708 POSITIVE (P-CLIENT-URL-SEARCHPARAMS-GET), and this directory's SCOPE CONTROL — a fixture
// the scanner never read reports zero findings exactly like one it scanned and missed, so the four
// negatives beside this file are only evidence while this row keeps firing.
//
// It is also the recall half of the receiver binding. The bound `$SP.get(...)` arm must still
// reach a locally-constructed URLSearchParams, which is the idiomatic App Router spelling and the
// one carbon's own production.kpi route uses (`new URLSearchParams(url.search)` — NOT
// `req.nextUrl.searchParams`, so the canonical request block's `$U.searchParams.get(...)` arm does
// not see it). The value is a client-supplied object key reaching Supabase Storage with no
// containment check: CWE-22 in a bucket.
declare const serviceClient: {
  storage: { from(bucket: string): { download(path: string): Promise<unknown> } };
};

export async function downloadExport(rawQueryString: string) {
  const searchParams = new URLSearchParams(rawQueryString);
  const objectKey = String(searchParams.get("key"));
  return serviceClient.storage.from("private").download(objectKey);
}
