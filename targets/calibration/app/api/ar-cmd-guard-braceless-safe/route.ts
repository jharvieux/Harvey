import { execSync } from "node:child_process";

const ALLOWED_ACTIONS = ["status", "uptime", "whoami"];

// N-AR-CMD-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the headline shape of the bug.
// This is how an App Router handler is actually written — `if (!ok) return Response.json(...)`,
// braceless, because the handler must RETURN the error response rather than write it to a `res`.
// The (a2) guards modelled only `if (!ok) { ... return; }`, so correct App Router code read as
// vulnerable in the framework Harvey's primary declared target uses. Paired with ar-cmd-guard-
// wrong-branch, whose guard returns on the passing branch and must keep firing.
export async function GET(request: Request) {
  const action = new URL(request.url).searchParams.get("action") ?? "";
  if (!ALLOWED_ACTIONS.includes(action)) return Response.json({ error: "unsupported" }, { status: 400 });

  const out = execSync(`/usr/local/bin/report ${action}`).toString();
  return Response.json({ out });
}
