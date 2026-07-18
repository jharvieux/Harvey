import * as ejs from "ejs";

// PLANTED BUG (P-SSTI-APPROUTER, #570): the EJS template string comes from the App Router JSON body
// (await req.json()) — the user controls the template SOURCE, not just the data (SSTI → RCE on EJS).
// The Express-only sources never connected to await req.json(). harvey-template-injection → review.
export async function POST(req: Request) {
  const { template, note } = await req.json();
  const html = ejs.render(String(template ?? ""), { note });
  return new Response(html, { headers: { "Content-Type": "text/html" } });
}
