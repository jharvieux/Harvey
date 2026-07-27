import { exec } from "node:child_process";

// PLANTED BUG (P-CMD-REQUEST-PARAM, #1221): the handler parameter is named `request`, the App
// Router convention. The old literal `req.` source form could not see `request.headers` at all —
// a rule that modelled Express shapes in a scanner aimed at the App Router (#1220).
export async function GET(request: Request) {
  const host = request.headers.get("x-forwarded-host");
  exec(`nslookup ${host}`);
  return new Response("ok");
}
