// NEGATIVE (N-EDGEFN-FALLBACK-ENV, #163): an env-to-env fallback — no literal at all, so there is
// nothing to ship in the bundle. harvey-edgefn-secret-fallback's pattern only matches a string
// literal on the ??/|| right-hand side; a second Deno.env.get() call doesn't match. Cleared.
Deno.serve(async (req) => {
  const INTERNAL_API_KEY = Deno.env.get("INTERNAL_API_KEY") || Deno.env.get("RESEND_API_KEY");
  const { to, subject } = await req.json();
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${INTERNAL_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ from: "noreply@example.com", to, subject }),
  });
  return new Response(await res.text(), { status: res.status });
});
