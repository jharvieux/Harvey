import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// PLANTED BUG (P-SIGNED-URL-TTL): a Supabase Storage signed URL minted with a 1-year expiry
// (31536000 s). A "temporary" link that lives for a year is effectively a public URL — anyone it
// leaks to (logs, Referer, shared history) can read the object until then. Semgrep
// harvey-signed-url-ttl (numeric-literal second arg > 7 days) → high. Distinct from B9's
// P-SIGNED-URL-TOKEN-SRC (a committed signed-URL token), which is a gitleaks value match.
export async function getReportUrl(path) {
  const { data } = await supabase.storage.from("reports").createSignedUrl(path, 31536000);
  return data.signedUrl;
}
