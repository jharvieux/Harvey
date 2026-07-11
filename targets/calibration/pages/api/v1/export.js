import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (SHADOW-API-VERSION): a deprecated v1 export route left live after /api/v2/export
// replaced it. v2 requires a bearer token; this old version never got the auth check, so it
// still serves every tenant's rows to anyone with only the anon key.
export default async function handler(req, res) {
  const { data } = await admin.from("documents").select("id, tenant_id, title");
  res.status(200).json(data);
}
