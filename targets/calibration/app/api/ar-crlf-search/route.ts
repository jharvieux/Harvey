import type { ServerResponse } from "node:http";

// PLANTED BUG (P-CRLF-SEARCHPARAMS, #1224): a query value reaches res.setHeader unfiltered, so
// CR/LF in it injects headers or splits the response. The rule modelled req.query/body/params/
// headers but neither searchParams nor the JSON body — every attacker-controlled STRING is in
// class for this sink, so there was nothing to weigh.
export async function GET(request: Request, res: ServerResponse) {
  const name = new URL(request.url).searchParams.get("name") ?? "";
  res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
  return new Response("ok");
}
