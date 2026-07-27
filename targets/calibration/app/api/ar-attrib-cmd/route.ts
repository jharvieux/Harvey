import { exec } from "node:child_process";

// PLANTED BUG (P-ATTRIB-APPROUTER-CMD, #1222): an App Router route handler reaching a shell-string
// exec. The finding must be ATTRIBUTED to harvey-command-injection — the app-layer rule, at its own
// Critical severity — and not to harvey-lib-command-injection.
//
// `export async function POST(...)` matched harvey-lib-*'s `export function $F($P, ...)` source, so
// before #1222 a route the app-layer rule could not see still produced a finding: Medium instead of
// Critical, described as "an exported library function's parameter", telling a client their public
// HTTP route is library-internal. The corpus danger is bigger than the severity — an entry scored
// on "did a relevant finding appear?" reads the gap as COVERED.
//
// This entry exists to fail if the attribution regresses, which is why its `match` is the rule id
// and its expectedSeverity is Critical: a lib-rule finding would satisfy neither.
export async function POST(request: Request) {
  const { host } = await request.json();
  exec(`nslookup ${host}`);
  return new Response("ok");
}
