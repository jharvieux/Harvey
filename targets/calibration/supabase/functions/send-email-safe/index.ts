// NEGATIVE (N-EDGEFN-SECRET-THROWS): the same Edge Function reading its secret from the env and
// failing closed when it is absent — no literal fallback. The harvey-edgefn-secret-fallback rule
// requires a string-literal `??` fallback, which is absent here, so it does not match. Cleared.
Deno.serve(async (req) => {
  const apiKey = Deno.env.get("RESEND_API_KEY");
  if (!apiKey) throw new Error("RESEND_API_KEY is not configured");
  const { to, subject } = await req.json();
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
    body: JSON.stringify({ from: "noreply@example.com", to, subject }),
  });
  return new Response(await res.text(), { status: res.status });
});
