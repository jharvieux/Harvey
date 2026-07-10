import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// TRUE NEGATIVE (N-SIGNED-URL-TTL-OK): a short 5-minute (300 s) expiry — the intended use of a
// signed URL. harvey-signed-url-ttl's metavariable-comparison fires only when the literal TTL
// exceeds a week, so this clears.
export async function getReportUrl(path) {
  const { data } = await supabase.storage.from("reports").createSignedUrl(path, 300);
  return data.signedUrl;
}
