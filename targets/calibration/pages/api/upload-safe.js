import { admin } from "../../lib/supabaseAdmin";

const ALLOWED_MIME = ["image/png", "image/jpeg"];
const MAX_SIZE = 5 * 1024 * 1024;

// Enforces a content-length cap and a MIME allowlist before the storage write.
export default async function handler(req, res) {
  const contentType = req.headers["content-type"];
  const length = Number(req.headers["content-length"]);
  if (!ALLOWED_MIME.includes(contentType) || length > MAX_SIZE) {
    return res.status(413).json({ error: "rejected" });
  }
  const buffer = Buffer.from(req.body);
  await admin.storage.from("uploads").upload(req.query.name, buffer, { contentType });
  res.status(200).json({ ok: true });
}
