// #1350 (audit of #1204's decline). The OWASP Node.js sheet's "use helmet middleware to set
// appropriate security headers" was declined as a library-adoption check — correctly: an app that
// sets the same headers by hand is right, and flagging the missing import is a false positive on
// working code. The decline's stated basis was that the headers are "checked by their effect
// instead (b5-headers)". MEASURED 2026-07-27, that was false for the app class the line is about:
// a bare Express app with neither helmet nor hand-set headers produced ZERO findings, while the
// same omission in a next.config.js headers() route produced three. harvey-missing-hsts,
// -frame-options and -nosniff all match `{ source: $S, headers: $ARR }` and say so in their own
// message text ("it reads this repository's next.config.js only"). So the effect check existed for
// Next and not for Express, and the gap was disclosed nowhere.
//
// This is that effect check, and it is deliberately NOT an adoption check: helmet clears it, and so
// does setting the headers by hand, because what is asked is whether the responses carry them — not
// which package put them there. `security-headers-by-hand.ts` is the fixture that holds this line;
// a firing on it fails the calibration gate loud.
//
// SAME-FILE HEURISTIC, disclosed in the finding rather than only here, matching the sibling passes
// (express-powered-by.ts, raw-body-limit.ts): headers set by a middleware module this pass did not
// read, or added at a reverse proxy / CDN / ingress, are outside what it can see. Hence review tier,
// and hence the evidence names the scope searched instead of asserting the responses ship bare.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";
import { appCreations, expressBindings } from "./express-powered-by.js";

// The four response headers whose absence is a defect rather than a preference, and the same four
// b5-headers checks a next.config.js for. A CSP `frame-ancestors` directive substitutes for
// X-Frame-Options, which is why any Content-Security-Policy mention clears the whole set: this pass
// asks "has anyone here thought about response headers at all", not "are all four present".
const SECURITY_HEADERS = [/^strict-transport-security$/i, /^x-frame-options$/i, /^x-content-type-options$/i, /^content-security-policy(-report-only)?$/i];

// Deliberately generous, same trade as raw-body-limit.ts and express-powered-by.ts: an over-eager
// clear is a false negative, an over-eager flag is a false positive on an app that is already
// correct — and #1204's ruling is explicit that an app handling this by hand must not be flagged.
// A `helmet` binding clears it because hidePoweredBy/hsts/noSniff/frameguard are all on by default.
function setsSecurityHeaders(sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isStringLiteralLike(n) && (n.text === "helmet" || SECURITY_HEADERS.some((h) => h.test(n.text)))) found = true;
    else if (ts.isIdentifier(n) && n.text === "helmet") found = true;
    if (!found) ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const bindings = expressBindings(sf);
  if (bindings.size === 0) return [];
  const creations = appCreations(sf, bindings);
  if (creations.length === 0 || setsSecurityHeaders(sf)) return [];

  // One row per module: the defect is "this app was never given a header posture", which a module
  // has once however many routers it builds.
  const node = creations[0]!;
  return [
    mechanicalFinding({
      id: `SEC-EXPRESS-HEADERS-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${node.getStart(sf)}`,
      title: "Express app sets no security response headers",
      severity: "Medium",
      category: "Configuration",
      taxonomy: "Express app sets no security response headers",
      location: `${path}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`,
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 60)}\` builds an Express app, and no Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options or Content-Security-Policy is set anywhere in ${path} — by any means, including a header middleware. SCOPE OF THIS CHECK: it reads the module that CONSTRUCTS the app and nothing else. Headers applied by a middleware module this pass did not read, or added at a reverse proxy, CDN or ingress in front of the app, are OUTSIDE what it can see — so a live response may well carry them. Confirm against the deployed response before treating these as absent. Note this is a check on the RESPONSE HEADERS, not on which package sets them: an app that sets them by hand clears it exactly as one mounting a header middleware does.`,
      impact:
        "Without HSTS a downgraded request can be intercepted over plain HTTP; without X-Frame-Options or a frame-ancestors directive the pages can be framed for clickjacking; without nosniff a browser may MIME-sniff a response into an executable content type. These are the browser-side defences that cost nothing to set and are absent by default in Express, which sets no security headers of its own.",
      fix: 'Set the headers once, at the top of the app — either by hand in a small middleware (`res.setHeader("Strict-Transport-Security", …)`, `X-Content-Type-Options`, `X-Frame-Options`, and a Content-Security-Policy) or with a header middleware, whichever fits the codebase. If they are already added at a proxy or CDN, setting them in the app too keeps it from depending on the edge staying configured.',
      precisionTier: "review",
    }),
  ];
}

export function detectExpressSecurityHeaderFindings(files: SourceInput[]): Finding[] {
  return files.flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
