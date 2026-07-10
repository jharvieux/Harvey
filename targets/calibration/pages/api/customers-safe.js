import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// NEGATIVE (N-SELECT-EXPLICIT): an explicit column projection — no select("*"), so nothing
// sensitive is spread. harvey-select-star-pii requires a "*" select source — cleared.
export default async function handler(req, res) {
  const { data } = await supabase.from("customers").select("id,name,email");
  res.json(data);
}
