import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-POSTGREST-FILTER-INJ): `n` is untrusted and interpolated into a string .or()
// filter expression — the attacker can inject extra PostgREST filter clauses. Review tier: the
// blast radius is scoped to the selected table. e.g. n=x,tenant_id.neq.00000000-...
export default async function handler(req, res) {
  const { n } = req.query;

  const { data } = await admin
    .from("documents")
    .select("id, title")
    .or(`name.eq.${n}`);

  res.status(200).json(data);
}
