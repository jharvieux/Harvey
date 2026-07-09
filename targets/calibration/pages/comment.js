import { admin } from "../lib/supabaseAdmin";

// PLANTED BUG (P-XSS-STORED-DSIH): a comment body READ FROM THE DATABASE flows straight into
// dangerouslySetInnerHTML with no sanitizer. Unlike P-XSS-DSIH (reflected, straight from the
// request), this is STORED XSS — an attacker plants the payload once (e.g. via a comment form)
// and every later viewer's browser executes it. Review tier: the taint source is a DB read, not
// the request itself, so a static rule can't confirm the write path was unsanitized too.
export default async function CommentPage({ params }) {
  const result = await admin.from("comments").select("content").eq("id", params.id).single();
  return <div dangerouslySetInnerHTML={{ __html: result.data.content }} />;
}
