import { execSync } from "node:child_process";

const ALLOWED_ACTIONS = ["status", "uptime", "whoami"];

// PLANTED BUG (P-AR-CMD-GUARD-WRONG-BRANCH, #1236 SOUNDNESS): the allowlist is exact, the guard is
// the braceless App Router early return the widened (a2) arm now clears — but the test is NOT
// negated, so the handler returns early on the values that PASS the allowlist and falls through to
// the shell with everything else. A guard sanitizer matched on the test alone, or on `if (…)`
// without the `!`, would clear this. It must STILL fire at high.
export async function GET(request: Request) {
  const action = new URL(request.url).searchParams.get("action") ?? "";
  if (ALLOWED_ACTIONS.includes(action)) return Response.json({ error: "unsupported" }, { status: 400 });

  const out = execSync(`/usr/local/bin/report ${action}`).toString();
  return Response.json({ out });
}
