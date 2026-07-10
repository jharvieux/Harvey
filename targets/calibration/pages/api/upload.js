import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-UPLOAD-NO-LIMIT): the request body is written to storage with no size cap and
// no MIME allowlist — an attacker can store arbitrarily large or executable content.
export default async function handler(req, res) {
  const buffer = Buffer.from(req.body);
  await admin.storage.from("uploads").upload(req.query.name, buffer);
  res.status(200).json({ ok: true });
}
