import * as ejs from "ejs";

// TRUE NEGATIVE (N-SSTI-APPROUTER-FIXED, #570): the template is a fixed server-owned constant; only
// the DATA passed to it comes from the request body. harvey-template-injection taints the template
// SOURCE argument (the first arg), which is the constant here, so no request taint reaches the sink
// — cleared. Regression guard for the new await-req.json() source.
const NOTE_TEMPLATE = "<h1><%= note.title %></h1><p><%= note.body %></p>";

export async function POST(req: Request) {
  const { note } = await req.json();
  const html = ejs.render(NOTE_TEMPLATE, { note });
  return new Response(html, { headers: { "Content-Type": "text/html" } });
}
