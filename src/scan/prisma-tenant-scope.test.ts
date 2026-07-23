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
});
