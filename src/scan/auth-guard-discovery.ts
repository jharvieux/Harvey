// #1300 / #126 option (1) — project-aware guard discovery.
//
// `harvey-route-noauth`'s and `harvey-authed-no-role-check`'s guard clause is a NAME test
// (ROUTE_NOAUTH_GUARD_RE / AUTHED_NO_ROLE_CHECK_GUARD_RE, src/scan/semgrep.ts): a call whose
// identifier carries a gate verb or an auth-ish token clears the finding. #126 measured 122 false
// positives on the ATC dogfood and recommended TWO fixes — "(1) [project-aware guard discovery] as
// the durable fix, with (2) [a `--auth-guards` allowlist] as an immediate mitigation". PR #127
// shipped a broader regex instead and filed no follow-up, justifying that with a quotation
// attributed to #126 that appears nowhere in it (VERIFIED 2026-07-30: `gh issue view 126` body +
// comments contain no "additional mitigation"; the only recommendation sentence is the one quoted
// above). This module is option (1).
//
// CORRECTION TO THE RECORD, MEASURED 2026-07-30 (semgrep 1.164.0, this repo's auth.yml): the
// residual is a false POSITIVE, not the "false negative" auth.yml:36-38 and #1300 both call it. A
// pages/api route whose only gate is `await mustBeOwner(req)` produces `harvey-route-noauth` at
// pages/api/widgets/delete.js:4-8 — the route IS guarded and Harvey reports it as unguarded. That
// is the same direction as #126's own title (122 FPs), and it matters because the two directions
// have opposite fixes.
//
// WHAT COUNTS AS A DISCOVERED GUARD. Five conditions, all required, and the narrowness is not
// caution — it is MEASURED. A wrongly-admitted name SILENCES a real missing-auth finding, and the
// first draft of this module did exactly that: MEASURED 2026-07-31 on targets/calibration, it
// discovered `handler`, `GET`, `getOrder`, `exportLedger` and `AdminPageSafe`, and the committed
// dry-run artifact lost 26 rows — 21 harvey-route-noauth and 5 harvey-authed-no-role-check —
// including the planted P-NOAUTH-BLOCK-COMMENT-GUARD and P-ROLE-BLOCK-COMMENT-GUARD positives. Two
// causes, both fixed below: a ROUTE ENTRY POINT that reads a session and returns 403 satisfies
// "looks like a guard", and the clearance test matched the DECLARATION `function handler(` as if it
// were a call, so such a route cleared itself.
//   1. the body calls a session/identity ACQUISITION primitive from a fixed vocabulary (not a loose
//      "mentions user" regex);
//   2. the body REJECTS — throw, a 401/403 status, redirect/notFound/forbidden/unauthorized;
//   3. the body performs NO data mutation. A guard authorises; it does not write. This is what
//      keeps `createUser(...)` — which reads a session and throws on a validation error — out;
//   4. the name is not a framework ENTRY POINT (handler/GET/POST/…/middleware/loader/action) and is
//      not Capitalised (a React component);
//   5. it is not DECLARED IN a route/page/middleware file. A guard is a shared helper; a function
//      declared inside the very file being judged is not evidence that the file is safe.

import ts from "typescript";
import { parse, type SourceInput } from "../detectors/common.js";

// Session/identity acquisition. A guard has to LOOK UP who the caller is before it can reject them.
const IDENTITY_CALL =
  /^(getServerSession|getSession|getToken|getUser|getAuthUser|getCurrentUser|getAuthenticatedUser|currentUser|auth|authenticate|useSession|verifyToken|verifyJwt|verifyJWT|jwtVerify|decodeToken|clerkClient|getAuth|requireSession|readSession)$/;
// `supabase.auth.getUser()` / `ctx.session.user` — identity reached through a property chain.
const IDENTITY_MEMBER = /\b(?:auth\.getUser|auth\.getSession|session\.user|user\.id|claims\.|token\.sub|locals\.user)\b/;
const REJECT_CALL = /^(forbidden|unauthorized|notFound|redirect|deny|reject403|throwForbidden)$/;
const REJECT_STATUS = /\b(401|403)\b/;
// A write through any of the ORMs/clients Harvey already routes on. A guard that mutates is not a
// guard, it is a handler — and admitting a handler name would silence real findings.
const MUTATION =
  /\.(delete|insert|update|upsert|create|createMany|updateMany|deleteMany|remove|save|destroy)\s*\(|\b(INSERT\s+INTO|UPDATE\s+|DELETE\s+FROM)\b/i;

function bodyOf(node: ts.Node): ts.Node | undefined {
  if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) return node.body;
  if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
    const init = node.initializer;
    if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return init.body;
  }
  return undefined;
}

function nameOf(node: ts.Node): string | undefined {
  if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) {
    return node.name !== undefined && ts.isIdentifier(node.name) ? node.name.text : undefined;
  }
  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) return node.name.text;
  return undefined;
}

function looksLikeGuard(body: ts.Node, text: string): boolean {
  if (MUTATION.test(text)) return false;

  let identity = IDENTITY_MEMBER.test(text);
  let rejects = REJECT_STATUS.test(text);
  const visit = (node: ts.Node): void => {
    if (ts.isThrowStatement(node)) rejects = true;
    if (ts.isCallExpression(node)) {
      const callee = ts.isIdentifier(node.expression)
        ? node.expression.text
        : ts.isPropertyAccessExpression(node.expression)
          ? node.expression.name.text
          : undefined;
      if (callee !== undefined) {
        if (IDENTITY_CALL.test(callee)) identity = true;
        if (REJECT_CALL.test(callee)) rejects = true;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(body);
  return identity && rejects;
}

// A framework entry point, or a React component. Neither is ever the guard that protects a route:
// the entry point IS the route, and a component reading a session and rendering 403 is a UI-only
// gate, the class #221 item 3 is about.
const ENTRY_POINT_NAME =
  /^(handler|middleware|default|GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|action|loader|clientAction|clientLoader|generateMetadata|generateStaticParams|[A-Z])/;
// Route/page/middleware modules. A guard declared here is local to the file under judgment, so it
// is not the shared helper this mechanism exists to recognise.
const ROUTE_FILE =
  /(^|\/)(pages\/api\/|pages\/|app\/.*\/(route|page|layout|template|default)\.[cm]?[jt]sx?$|middleware\.[cm]?[jt]sx?$|route\.[cm]?[jt]sx?$)/;

// Function names in the TARGET's own source that behave like authorization guards. Returned as bare
// identifiers; src/scan/semgrep.ts folds them into the guard-token test for that scan only.
export function discoverAuthGuards(sources: readonly SourceInput[]): string[] {
  const names = new Set<string>();
  for (const file of sources) {
    if (ROUTE_FILE.test(file.path)) continue;
    if (!/\b(session|auth|token|user|permission|role|guard|owner|member|tenant|forbidden|401|403)\b/i.test(file.text)) {
      continue; // cheap pre-filter: a file with no auth vocabulary at all holds no guard
    }
    const sf = parse(file.path, file.text);
    const visit = (node: ts.Node): void => {
      const body = bodyOf(node);
      const name = nameOf(node);
      if (body !== undefined && name !== undefined && !ENTRY_POINT_NAME.test(name) && looksLikeGuard(body, body.getText(sf))) {
        names.add(name);
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(sf, visit);
  }
  return [...names].sort();
}
