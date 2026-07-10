import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// PLANTED BUG (P-SELECT-STAR-PII): select("*") from a table holding PII (ssn) is serialized whole
// into the API response — every column, including sensitive ones the client never needed, leaks.
// harvey-select-star-pii (taint select("*") -> res.json).
export default async function handler(req, res) {
  const { data } = await supabase.from("customers").select("*");
  res.json(data);
}
