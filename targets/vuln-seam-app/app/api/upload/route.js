// PLANTED BUG (UPLOAD-DISGUISED-TYPE + UPLOAD-PATH-TRAVERSAL, #635/#1686): a permissive file-upload
// endpoint that accepts any bytes under any declared content-type and echoes the client-supplied
// filename verbatim as the stored key — no magic-byte validation, no filename sanitization. The
// upload-attack suite's disguised-type probe (HTML bytes declared image/png) and path-traversal probe
// (../../ filename surviving into the stored key) both reach `vulnerable`. See ./safe for the control.
export const dynamic = "force-dynamic";

export async function POST(request) {
  const form = await request.formData().catch(() => null);
  const file = form?.get("file");
  const name = file && typeof file === "object" && "name" in file ? file.name : "upload.bin";
  // Stored under the raw client filename — a `../` traversal survives into the returned key.
  return Response.json({ ok: true, path: name });
}
