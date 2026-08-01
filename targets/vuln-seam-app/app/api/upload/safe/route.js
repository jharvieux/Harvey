// NEGATIVE CONTROL (UPLOAD-* must stay not-vulnerable, #635/#1686): the hardened twin of ../route.js.
// It validates the declared image content-type against the leading magic bytes (rejecting HTML-as-png),
// sanitizes the filename to a bare basename (stripping any ../ traversal), and returns the file with
// Content-Disposition: attachment so an uploaded SVG/HTML can never be served inline.
export const dynamic = "force-dynamic";

const IMAGE_MAGIC = {
  "image/png": [0x89, 0x50, 0x4e, 0x47],
  "image/jpeg": [0xff, 0xd8, 0xff],
  "image/gif": [0x47, 0x49, 0x46],
};

export async function POST(request) {
  const form = await request.formData().catch(() => null);
  const file = form?.get("file");
  if (!file || typeof file !== "object" || !("arrayBuffer" in file)) {
    return new Response(JSON.stringify({ error: "no file" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const magic = IMAGE_MAGIC[file.type];
  if (magic && !magic.every((b, i) => bytes[i] === b)) {
    return new Response(JSON.stringify({ error: "content does not match declared type" }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
  const safe = String(file.name || "upload.bin").split(/[/\\]/).pop().replace(/^\.+/, "") || "upload.bin";
  return new Response(JSON.stringify({ ok: true, path: safe }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Content-Disposition": "attachment" },
  });
}
