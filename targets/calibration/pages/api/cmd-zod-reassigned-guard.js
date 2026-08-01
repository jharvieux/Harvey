import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-REASSIGNED-GUARD, #1630 SOUNDNESS): the reason the new schema arm binds a
// `const` DECLARATION and not a bare `$RE = $LIT` assignment. The anchored literal is no longer in
// force by the time the schema is built — `.regex(/.*/)` accepts `status; rm -rf /` — so a bare
// assignment binding would satisfy the anchoring constraint from a dead literal and clear a live
// injection. The `let` spelling is deliberately left drawing the finding: an over-report, never a
// missed bug. Must fire.
export default async function handler(req, res) {
  let action = /^[a-z]+$/;
  action = /.*/;
  const parsed = z.string().regex(action).safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
