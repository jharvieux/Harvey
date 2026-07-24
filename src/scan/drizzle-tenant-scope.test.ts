import { describe, expect, it } from "vitest";
import { detectDrizzleTenantScopeFindings } from "./drizzle-tenant-scope.js";

// Each negative differs from the positive by exactly one gate, so a single-gate regression fails a
// specific test rather than only the whole-target calibration count.

const positive = `import { eq } from "drizzle-orm";
import { db } from "./client";
import { tasks } from "./schema";
export async function getTask(id: string) {
  return db.select().from(tasks).where(eq(tasks.id, id));
}
`;

const file = (text: string, path = "src/db/task-repo.ts") => [{ path, text }];

describe("drizzle-tenant-scope (#901 — Drizzle query filtered by primary key alone, no tenant scope)", () => {
  it("flags the unscoped select at review tier, naming the verb", () => {
    const findings = detectDrizzleTenantScopeFindings(file(positive));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review" });
    expect(findings[0]?.evidence).toContain("drizzle-tenant-scope");
    expect(findings[0]?.title).toContain("Drizzle `select`");
  });

  it("stays silent when the where also filters on a tenant column via and()", () => {
    const scoped = positive.replace("where(eq(tasks.id, id))", "where(and(eq(tasks.id, id), eq(tasks.organizationId, org)))");
    expect(detectDrizzleTenantScopeFindings(file(scoped))).toHaveLength(0);
  });

  it("catches the update and delete builder chains too", () => {
    const update = `export const f = (id: string) => db.update(tasks).set({ name }).where(eq(tasks.id, id));`;
    const del = `export const f = (id: string) => db.delete(tasks).where(eq(tasks.id, id));`;
    expect(detectDrizzleTenantScopeFindings(file(update)), "update").toHaveLength(1);
    expect(detectDrizzleTenantScopeFindings(file(del)), "delete").toHaveLength(1);
  });

  it("stays silent when the filter is not a primary-key lookup", () => {
    const bySlug = positive.replace("eq(tasks.id, id)", "eq(tasks.slug, slug)");
    expect(detectDrizzleTenantScopeFindings(file(bySlug))).toHaveLength(0);
  });

  it("does not treat a tenant id on the VALUE side of the id comparison as a scope", () => {
    // eq(tasks.id, ctx.organizationId) filters the primary key by a tenant-looking VALUE — still
    // unscoped (the row is chosen by id alone), so it must still fire.
    const valueSide = positive.replace("eq(tasks.id, id)", "eq(tasks.id, ctx.organizationId)");
    expect(detectDrizzleTenantScopeFindings(file(valueSide))).toHaveLength(1);
  });

  it("does not fire on a same-shaped chain rooted at a non-client object", () => {
    const notDb = positive.replace("db.select()", "cache.select()");
    expect(detectDrizzleTenantScopeFindings(file(notDb))).toHaveLength(0);
  });

  it("does not fire on a Knex-style object where clause (no eq() column call)", () => {
    // Knex uses db.select().from('t').where({ id }) — no eq(col, …) call, so no filtered column is
    // extracted and the detector stays silent (this is a recognised non-Drizzle query builder).
    const knex = `export const f = (id: string) => db.select().from(tasks).where({ id });`;
    expect(detectDrizzleTenantScopeFindings(file(knex))).toHaveLength(0);
  });

  it("fires through a `this.db`/`ctx.db` client accessor", () => {
    const viaThis = `export const f = (id: string) => this.db.select().from(tasks).where(eq(tasks.id, id));`;
    const viaCtx = `export const f = (id: string) => ctx.db.delete(tasks).where(eq(tasks.id, id));`;
    expect(detectDrizzleTenantScopeFindings(file(viaThis))).toHaveLength(1);
    expect(detectDrizzleTenantScopeFindings(file(viaCtx))).toHaveLength(1);
  });
});
