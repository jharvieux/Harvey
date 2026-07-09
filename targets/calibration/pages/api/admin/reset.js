import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-DEBUG-ENDPOINT): an admin route whose "authorization" is a hardcoded
// `const isAdmin = true`, i.e. no real check at all. Caught by the leftover-auth grep
// (isAdmin hardcoded to true) and the sensitive-route heuristic (/admin + no auth call).
export default async function handler(req, res) {
  const isAdmin = true;
  if (!isAdmin) return res.status(403).json({ error: "forbidden" });

  await admin.from("counters").update({ value: 0 }).neq("id", "00000000-0000-0000-0000-000000000000");
  res.status(200).json({ reset: true });
}
