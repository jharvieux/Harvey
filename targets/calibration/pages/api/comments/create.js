import { admin } from "../../../lib/supabaseAdmin";

export default async function handler(req, res) {
  // PLANTED BUG (P-TODO-AUTH): the auth check was never written — a left-open mutation.
  // TODO: auth — verify the caller owns req.body.tenant_id before inserting.
  const { data } = await admin
    .from("notes")
    .insert({ title: req.body.title, tenant_id: req.body.tenant_id })
    .select();

  res.status(200).json({ created: data });
}
