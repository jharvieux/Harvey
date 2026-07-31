// #1300 / #126 option (1). The failing direction is BOTH ways and both matter:
//   - a house-style guard must be discovered, or the route-noauth FP #126 measured 122 of survives;
//   - a mutating handler that happens to read a session and throw must NOT be discovered, because
//     a wrongly-admitted name SILENCES a real missing-auth finding, which is worse than the FP.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { discoverAuthGuards } from "./auth-guard-discovery.js";
import { partitionGuardTokenSuppressed } from "./semgrep.js";

const GUARD_MODULE = `
import { getServerSession } from "next-auth";
export async function mustBeOwner(req) {
  const session = await getServerSession(req);
  if (!session || session.user.role !== "owner") {
    const err = new Error("Forbidden");
    err.status = 403;
    throw err;
  }
  return session;
}
export function slugify(value) {
  return String(value).toLowerCase();
}
`;

describe("discoverAuthGuards (#1300)", () => {
  it("discovers a house-style guard whose name matches neither built-in bucket", () => {
    const names = discoverAuthGuards([{ path: "lib/guards.js", text: GUARD_MODULE }]);
    expect(names).toContain("mustBeOwner");
    expect(names).not.toContain("slugify");
  });

  it("discovers the arrow-function form too", () => {
    const names = discoverAuthGuards([
      {
        path: "lib/gate.ts",
        text: `
          import { auth } from "@/auth";
          export const onlyTeamLead = async () => {
            const session = await auth();
            if (!session) throw new Error("nope");
            return session;
          };
        `,
      },
    ]);
    expect(names).toContain("onlyTeamLead");
  });

  it("does NOT admit a mutating handler that reads a session and throws — that would silence a real finding", () => {
    const names = discoverAuthGuards([
      {
        path: "lib/users.ts",
        text: `
          import { getServerSession } from "next-auth";
          export async function createUser(req) {
            const session = await getServerSession(req);
            if (!req.body.email) throw new Error("email required");
            return db.from("users").insert({ email: req.body.email, by: session.user.id });
          }
        `,
      },
    ]);
    expect(names).not.toContain("createUser");
  });

  it("does NOT admit a function that rejects without ever looking up an identity", () => {
    const names = discoverAuthGuards([
      { path: "lib/validate.ts", text: `export function assertPositive(n) { if (n <= 0) throw new Error("bad"); return n; }` },
    ]);
    expect(names).not.toContain("assertPositive");
  });
});

describe("partitionGuardTokenSuppressed with project guards (#1300)", () => {
  const withRoute = (body: string): { dir: string; file: string; lines: number } => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-project-guard-"));
    const file = join(dir, "delete.js");
    writeFileSync(file, body);
    return { dir, file, lines: body.split("\n").length };
  };

  const ROUTE = [
    "export default async function handler(req, res) {",
    "  await mustBeOwner(req);",
    '  await admin.from("widgets").delete().eq("id", req.body.id);',
    "}",
  ].join("\n");

  it("a route guarded only by a discovered house-style helper is cleared", () => {
    const { dir, file, lines } = withRoute(ROUTE);
    try {
      const { reported, guarded } = partitionGuardTokenSuppressed(
        { results: [{ check_id: "harvey-route-noauth", path: file, start: { line: 1 }, end: { line: lines } }] },
        ["mustBeOwner"],
      );
      expect(reported).toEqual([]);
      expect(guarded).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the same route with NO project guards supplied is still reported — the pre-#1300 behaviour", () => {
    const { dir, file, lines } = withRoute(ROUTE);
    try {
      const { reported, guarded } = partitionGuardTokenSuppressed({
        results: [{ check_id: "harvey-route-noauth", path: file, start: { line: 1 }, end: { line: lines } }],
      });
      expect(guarded).toEqual([]);
      expect(reported).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a project guard name does not clear an unrelated identifier that merely contains it", () => {
    const { dir, file, lines } = withRoute(
      ["export default async function handler(req, res) {", "  const h = authorHistory(req);", "  await admin.from('w').delete();", "}"].join("\n"),
    );
    try {
      const { reported } = partitionGuardTokenSuppressed(
        { results: [{ check_id: "harvey-route-noauth", path: file, start: { line: 1 }, end: { line: lines } }] },
        ["author"],
      );
      expect(reported).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
