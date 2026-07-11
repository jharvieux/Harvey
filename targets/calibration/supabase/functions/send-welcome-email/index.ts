// NEGATIVE (N-EDGEFN-FALLBACK-URL, #163): a Deno.env.get() fallback whose literal is a URL, not a
// secret — the deployed bundle never ships a credential here. harvey-edgefn-secret-fallback now
// requires the fallback literal to be secret-shaped (known key prefix or long hex/base64 blob), so
// this URL literal doesn't match. Cleared.
Deno.serve(async (req) => {
  const APP_URL = Deno.env.get("APP_URL") || "https://my-app.vercel.app";
  const { to } = await req.json();
  return new Response(JSON.stringify({ to, link: `${APP_URL}/welcome` }), { status: 200 });
});
