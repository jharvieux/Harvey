import { admin } from "../../../lib/supabaseAdmin";

// SHADOW-API-VERSION negative: the current export route rejects unauthenticated callers.
export default async function handler(req, res) {
  if (!req.headers.authorization) {
    return res.status(401).json({ error: "auth required" });
  }
  const { data } = await admin.from("documents").select("id, tenant_id, title");
  res.status(200).json(data);
}
