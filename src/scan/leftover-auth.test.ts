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
});
