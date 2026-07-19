import { describe, expect, it } from "vitest";
import { classifyLeftoverAuth } from "./leftover-auth.js";

describe("classifyLeftoverAuth", () => {
  it("flags a TODO: auth comment", () => {
    const findings = classifyLeftoverAuth({ path: "lib/x.ts", content: "// TODO: auth\nexport function f() {}" });
    expect(findings.some((f) => f.taxonomy === "Leftover-auth grep")).toBe(true);
  });

  it("flags if (true) guards", () => {
    const findings = classifyLeftoverAuth({ path: "lib/y.ts", content: "if (true) { return next(); }" });
    expect(findings.some((f) => f.title.includes("if (true)"))).toBe(true);
  });

  it("flags a hardcoded isAdmin = true", () => {
    const findings = classifyLeftoverAuth({ path: "lib/z.ts", content: "const isAdmin = true;" });
    expect(findings.some((f) => f.title.includes("isAdmin"))).toBe(true);
  });

  it("flags bypassAuth references", () => {
    const findings = classifyLeftoverAuth({ path: "lib/w.ts", content: "if (bypassAuth) return;" });
    expect(findings.some((f) => f.title.includes("bypassAuth"))).toBe(true);
  });

  it("returns no findings for clean, unrelated source", () => {
    expect(classifyLeftoverAuth({ path: "lib/clean.ts", content: "export const add = (a: number, b: number) => a + b;" })).toEqual([]);
  });

  it("flags an admin route file with no auth-call hint", () => {
    const findings = classifyLeftoverAuth({ path: "app/api/admin/users/route.ts", content: "export async function GET() { return Response.json(await db.users.findMany()); }" });
    expect(findings.some((f) => f.taxonomy === "Unauthenticated debug/admin route")).toBe(true);
  });

  it("does not flag an admin route file that does call an auth check", () => {
    const findings = classifyLeftoverAuth({
      path: "app/api/admin/users/route.ts",
      content: "export async function GET() { const session = await getServerSession(); if (!session) return unauthorized(); return Response.json(await db.users.findMany()); }",
    });
    expect(findings.some((f) => f.taxonomy === "Unauthenticated debug/admin route")).toBe(false);
  });

  it("does not flag a non-sensitive route path even with no auth hint", () => {
    const findings = classifyLeftoverAuth({ path: "app/api/products/route.ts", content: "export async function GET() { return Response.json([]); }" });
    expect(findings.some((f) => f.taxonomy === "Unauthenticated debug/admin route")).toBe(false);
  });

  it("flags a login route file with no rate-limiter hint", () => {
    const findings = classifyLeftoverAuth({ path: "pages/api/auth/login.js", content: "export default async function handler(req, res) { res.json({ ok: true }); }" });
    expect(findings.some((f) => f.taxonomy === "Missing rate limit on auth endpoint")).toBe(true);
  });

  it("does not flag a login route file that calls a rate limiter", () => {
    const findings = classifyLeftoverAuth({
      path: "pages/api/auth/login.js",
      content: "export default async function handler(req, res) { const ok = await rateLimit(req); if (!ok) return res.status(429).end(); res.json({ ok: true }); }",
    });
    expect(findings.some((f) => f.taxonomy === "Missing rate limit on auth endpoint")).toBe(false);
  });

  it("does not flag a non-auth route path for missing rate limiting", () => {
    const findings = classifyLeftoverAuth({ path: "pages/api/products/list.js", content: "export default async function handler(req, res) { res.json([]); }" });
    expect(findings.some((f) => f.taxonomy === "Missing rate limit on auth endpoint")).toBe(false);
  });

  it("all findings from a single file get distinct ids", () => {
    const findings = classifyLeftoverAuth({ path: "lib/multi.ts", content: "// TODO: auth\nif (true) {}\nconst isAdmin = true;\nbypassAuth();" });
    const ids = findings.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  // --- B14 app-logic heuristics (all review tier) ---
  const has = (fs: ReturnType<typeof classifyLeftoverAuth>, tax: string) => fs.some((f) => f.taxonomy === tax);

  it("flags an authz decision made from a client-controlled header, not a session role", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/p.js", content: "if (req.headers['x-role'] === 'admin') grant();" }), "Authz decision from client-controlled input")).toBe(true);
    expect(has(classifyLeftoverAuth({ path: "pages/api/p.js", content: "if (user.app_metadata.role === 'admin') grant();" }), "Authz decision from client-controlled input")).toBe(false);
  });

  it("flags a payment amount taken from the request, not recomputed from the DB", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/c.js", content: "stripe.paymentIntents.create({ amount: req.body.amount });" }), "Client-supplied payment amount trusted by server")).toBe(true);
    expect(has(classifyLeftoverAuth({ path: "pages/api/c.js", content: "stripe.paymentIntents.create({ amount: price * req.body.qty });" }), "Client-supplied payment amount trusted by server")).toBe(false);
  });

  it("flags a password/secret written to the console, not an outcome-only log", () => {
    expect(has(classifyLeftoverAuth({ path: "lib/a.js", content: "console.log('login', { email, password });" }), "Sensitive value logged to console")).toBe(true);
    expect(has(classifyLeftoverAuth({ path: "lib/a.js", content: "console.log('login', { email, success });" }), "Sensitive value logged to console")).toBe(false);
  });

  it("flags a storage upload with no size/MIME limit, and clears one that is guarded", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/u.js", content: "await sb.storage.from('x').upload(name, buf);" }), "Upload to storage with no size/MIME limit")).toBe(true);
    expect(has(classifyLeftoverAuth({ path: "pages/api/u.js", content: "if (len > MAX_SIZE) return; await sb.storage.from('x').upload(name, buf, { contentType });" }), "Upload to storage with no size/MIME limit")).toBe(false);
  });

  it("flags a webhook route doing a privileged write with no signature check", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/webhooks/in.js", content: "await admin.from('t').update({ x: req.body.x });" }), "Inbound webhook with no signature verification")).toBe(true);
  });

  it("does not flag a webhook route that verifies an HMAC signature first", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/webhooks/in.js", content: "const e = stripe.webhooks.constructEvent(b, sig, secret); await admin.from('t').update({ x: 1 });" }), "Inbound webhook with no signature verification")).toBe(false);
  });

  it("does not flag a non-webhook admin-write route as a missing-signature webhook", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/settings/delete.js", content: "await admin.from('settings').delete().eq('key', req.body.key);" }), "Inbound webhook with no signature verification")).toBe(false);
  });

  // #353 UPDATE-UNSCOPED
  const UNSCOPED = "Unscoped service-role UPDATE/DELETE (no WHERE)";
  it("flags a raw UPDATE with no WHERE on a query sink in a route file", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/profile/update.js", content: 'await pool.query("UPDATE public.profiles SET role = $1", [role]);' }), UNSCOPED)).toBe(true);
  });

  it("does not flag the same UPDATE once it is scoped with a WHERE clause", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/profile/update.js", content: 'await pool.query("UPDATE public.profiles SET role = $1 WHERE id = $2", [role, id]);' }), UNSCOPED)).toBe(false);
  });

  it("is not fooled by a comment that mentions WHERE next to an actually-unscoped UPDATE", () => {
    // The FP the first regex hit: a nearby comment saying "WHERE" masked the missing clause.
    const content = '// a correct version would scope with WHERE id = $2\nawait pool.query("DELETE FROM public.profiles", []);';
    expect(has(classifyLeftoverAuth({ path: "pages/api/profile/purge.js", content }), UNSCOPED)).toBe(true);
  });

  it("does not flag an unscoped UPDATE string that is never handed to a query sink", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/x.js", content: 'const label = "UPDATE available";' }), UNSCOPED)).toBe(false);
  });

  // #354 P-MW-MATCHER-EXCLUDES-API
  const MATCHER = "Middleware matcher excludes /api routes";
  it("flags a middleware matcher whose lookahead excludes /api", () => {
    expect(has(classifyLeftoverAuth({ path: "middleware.ts", content: 'export const config = { matcher: "/((?!api|_next/static).*)" };' }), MATCHER)).toBe(true);
  });

  it("does not flag a matcher whose lookahead has no api exclusion", () => {
    expect(has(classifyLeftoverAuth({ path: "middleware.ts", content: 'export const config = { matcher: "/((?!_next/static|favicon.ico).*)" };' }), MATCHER)).toBe(false);
  });

  // #354 P-DRAFTMODE-NO-SECRET
  const DRAFTMODE = "draftMode().enable() reachable with no secret";
  it("flags draftMode().enable() with no secret check", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/preview/enable.js", content: "draftMode().enable(); res.json({ preview: true });" }), DRAFTMODE)).toBe(true);
  });

  it("does not flag draftMode().enable() gated by a secret comparison", () => {
    expect(has(classifyLeftoverAuth({ path: "pages/api/preview/enable.js", content: "if (req.query.secret !== process.env.PREVIEW_SECRET) return; draftMode().enable();" }), DRAFTMODE)).toBe(false);
  });

  // #568 — sensitive-route AUTH_HINT recognizes bare session-accessor wrappers.
  const SENSITIVE = "Unauthenticated debug/admin route";
  it("does not flag an admin route guarded by a bare getUser() wrapper", () => {
    const findings = classifyLeftoverAuth({ path: "app/api/admin/revenue/route.ts", content: "export async function GET(req) { const user = await getUser(req); if (!user) return unauthorized(); return Response.json(await db.all()); }" });
    expect(has(findings, SENSITIVE)).toBe(false);
  });

  it("still flags a sensitive route with no session read of any name", () => {
    const findings = classifyLeftoverAuth({ path: "app/api/admin/revenue/route.ts", content: "export async function GET() { return Response.json(await db.all()); }" });
    expect(has(findings, SENSITIVE)).toBe(true);
  });

  // #576 — client-trust-boundary: a role/privilege decision made in client code.
  const CLIENT_AUTHZ = "Client-side authorization decision";
  it("flags an admin gate read from Web Storage", () => {
    expect(has(classifyLeftoverAuth({ path: "src/App.tsx", content: "const role = localStorage.getItem('role'); if (role === 'admin') return <Admin/>;" }), CLIENT_AUTHZ)).toBe(true);
  });

  it("flags a localStorage.role property compared to a privilege literal", () => {
    expect(has(classifyLeftoverAuth({ path: "src/App.tsx", content: "if (localStorage.role === 'owner') { showOwnerTools(); }" }), CLIENT_AUTHZ)).toBe(true);
  });

  it("flags a client component gating navigation on a user-object role field", () => {
    const content = "const navigate = useNavigate(); if (user.user_metadata.role !== 'admin') return null; navigate('/admin');";
    expect(has(classifyLeftoverAuth({ path: "src/Route.tsx", content }), CLIENT_AUTHZ)).toBe(true);
  });

  it("does not flag a server-side role check (no client nav/render gate)", () => {
    const content = "const { data: profile } = await admin.from('profiles').select('role').eq('id', user.id).single(); if (profile.role !== 'admin') return new Response('Forbidden', { status: 403 });";
    expect(has(classifyLeftoverAuth({ path: "src/lib/requireAdmin.ts", content }), CLIENT_AUTHZ)).toBe(false);
  });

  it("does not flag a role read from a non-storage variable with no privilege comparison", () => {
    expect(has(classifyLeftoverAuth({ path: "src/App.tsx", content: "const role = session.role; return <span>{role}</span>;" }), CLIENT_AUTHZ)).toBe(false);
  });
});
