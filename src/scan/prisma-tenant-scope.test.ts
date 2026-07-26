import { describe, expect, it } from "vitest";
import { detectPrismaTenantScopeFindings } from "./prisma-tenant-scope.js";

// Each negative differs from the positive by exactly one gate, so a single-gate regression fails a
// specific test rather than only the whole-target calibration count.

const positive = `import { prisma } from "./client";
export async function deleteTask(id: string) {
  return prisma.task.delete({ where: { id } });
}
`;

const file = (text: string, path = "src/db/task-repo.ts") => [{ path, text }];

describe("prisma-tenant-scope (#760 — Prisma query filtered by primary key alone, no tenant scope)", () => {
  it("flags the unscoped delete at review tier, naming the model and verb", () => {
    const findings = detectPrismaTenantScopeFindings(file(positive));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review" });
    expect(findings[0]?.evidence).toContain("prisma-tenant-scope");
    expect(findings[0]?.title).toContain("prisma.task.delete");
  });

  it("stays silent when the where carries a tenant column", () => {
    const scoped = positive.replace("{ where: { id } }", "{ where: { id, organizationId } }");
    expect(detectPrismaTenantScopeFindings(file(scoped))).toHaveLength(0);
  });

  it("clears a tenant scope nested under a relation filter", () => {
    const relational = positive.replace(
      "{ where: { id } }",
      "{ where: { id, organization: { members: { some: { userId: ctx.userId } } } } }",
    );
    expect(detectPrismaTenantScopeFindings(file(relational))).toHaveLength(0);
  });

  it("catches every scoped verb (findUnique/findFirst/update/updateMany/deleteMany)", () => {
    for (const verb of ["findUnique", "findFirst", "update", "updateMany", "deleteMany"]) {
      const text = `export const f = () => prisma.task.${verb}({ where: { id } });`;
      expect(detectPrismaTenantScopeFindings(file(text)), verb).toHaveLength(1);
    }
  });

  it("stays silent on non-selecting verbs (create/findMany)", () => {
    const create = `export const f = () => prisma.task.create({ data: { id, name } });`;
    const findMany = `export const f = () => prisma.task.findMany();`;
    expect(detectPrismaTenantScopeFindings(file(create))).toHaveLength(0);
    expect(detectPrismaTenantScopeFindings(file(findMany))).toHaveLength(0);
  });

  it("stays silent when the filter is not a primary-key lookup", () => {
    const bySlug = positive.replace("{ where: { id } }", "{ where: { slug } }");
    expect(detectPrismaTenantScopeFindings(file(bySlug))).toHaveLength(0);
  });

  it("does not fire on a same-shaped call on a non-Prisma-named object", () => {
    const notPrisma = positive.replace("prisma.task.delete", "cache.task.delete");
    expect(detectPrismaTenantScopeFindings(file(notPrisma))).toHaveLength(0);
  });

  it("fires through a `this.prisma`/`ctx.db` client accessor", () => {
    const viaThis = `export const f = () => this.prisma.task.delete({ where: { id } });`;
    const viaCtx = `export const f = () => ctx.db.task.delete({ where: { id } });`;
    expect(detectPrismaTenantScopeFindings(file(viaThis))).toHaveLength(1);
    expect(detectPrismaTenantScopeFindings(file(viaCtx))).toHaveLength(1);
  });

  // #911: an app built on a tenant-scoping wrapper library still drew this finding, because the
  // wrapper injects the predicate at runtime and the AST at the call site can't see it.
  // #1067: the gate no longer returns [] — an empty result is indistinguishable from "assessed and
  // clean", so it now returns the M1-WRAPPER-00 disclosure counting what it withheld.
  describe("wrapper-injected gate (#911) discloses instead of going silent (#1067)", () => {
    it("names the wrapper dependency and its section, and counts the withheld call sites", () => {
      const files = [
        { path: "package.json", text: JSON.stringify({ dependencies: { "@zenstackhq/runtime": "^2.0.0" } }) },
        { path: "src/db/task-repo.ts", text: positive },
      ];
      const findings = detectPrismaTenantScopeFindings(files);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.id).toBe("M1-WRAPPER-00");
      expect(findings[0]?.severity).toBe("Info");
      expect(findings[0]?.evidence).toContain("@zenstackhq/runtime (dependencies)");
      expect(findings[0]?.evidence).toContain("1 call site");
      expect(findings[0]?.evidence).toContain("src/db/task-repo.ts");
    });

    // The devDependency case is the one that matters most: a wrapper used only in tests would
    // otherwise switch the production detector off with nothing said about it.
    it("says so when the only signal is a devDependency", () => {
      const files = [
        { path: "package.json", text: JSON.stringify({ devDependencies: { "prisma-rls": "^1.0.0" } }) },
        { path: "src/db/task-repo.ts", text: positive },
      ];
      const findings = detectPrismaTenantScopeFindings(files);
      expect(findings.map((f) => f.id)).toEqual(["M1-WRAPPER-00"]);
      expect(findings[0]?.evidence).toContain("prisma-rls (devDependencies)");
    });

    it("names the file when the signal is an in-tree $extends(...).$allOperations wrapper", () => {
      const wrapper = `export const db = prisma.$extends({ query: { $allModels: { async $allOperations({ args, query }) { return query(args); } } } });`;
      const files = [
        { path: "src/lib/rls.ts", text: wrapper },
        { path: "src/db/task-repo.ts", text: positive },
      ];
      const findings = detectPrismaTenantScopeFindings(files);
      expect(findings.map((f) => f.id)).toEqual(["M1-WRAPPER-00"]);
      expect(findings[0]?.evidence).toContain("src/lib/rls.ts vendors the $extends");
    });

    it("discloses zero withheld call sites rather than nothing, when the wrapper target has none", () => {
      const files = [{ path: "package.json", text: JSON.stringify({ dependencies: { zenstack: "^2.0.0" } }) }];
      const findings = detectPrismaTenantScopeFindings(files);
      expect(findings.map((f) => f.id)).toEqual(["M1-WRAPPER-00"]);
      expect(findings[0]?.evidence).toContain("0 call sites");
    });

    it("still fires the real finding when no wrapper dependency or in-tree extension is present", () => {
      expect(detectPrismaTenantScopeFindings(file(positive))).toHaveLength(1);
    });

    it("does not suppress on an unrelated package.json (no recognized wrapper dependency)", () => {
      const files = [
        { path: "package.json", text: JSON.stringify({ dependencies: { "@prisma/client": "^5.0.0" } }) },
        { path: "src/db/task-repo.ts", text: positive },
      ];
      expect(detectPrismaTenantScopeFindings(files)).toHaveLength(1);
    });
  });
});
