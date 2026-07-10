// PLANTED BUG (P-EDGEFN-SECRET): a Supabase Edge Function that falls back to a hardcoded secret
// literal when the env var is missing, instead of failing closed. The literal ships in the
// deployed function bundle and its git history. Value is FAKE (a Resend re_… key shape). Semgrep
// harvey-edgefn-secret-fallback matches the `Deno.env.get(...) ?? "<literal>"` fallback → high.
Deno.serve(async (req) => {
  const apiKey = Deno.env.get("RESEND_API_KEY") ?? "re_FAKE1234abcd5678efgh9012ijkl3456";
  const { to, subject } = await req.json();
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
    body: JSON.stringify({ from: "noreply@example.com", to, subject }),
  });
  return new Response(await res.text(), { status: res.status });
});
