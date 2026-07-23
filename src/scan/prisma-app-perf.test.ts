import { describe, expect, it } from "vitest";
import { detectPrismaAppPerfFindings } from "./prisma-app-perf.js";

// Each negative differs from the positive by exactly one gate, so a single-gate regression fails a
// specific test rather than only the whole-scan finding count.

const schema = `
  model User {
    id     String @id @default(cuid())
    email  String @unique
    tenantId String
    notes  Note[]
  }
  model Note {
    id       String @id @default(cuid())
    title    String
    status   String
    tenantId String
    userId   String
    user     User   @relation(fields: [userId], references: [id])
    @@index([tenantId])
  }
`;

const file = (text: string, path = "src/lib/notes.ts") => [{ path, text }];

describe("prisma-app-perf N+1 query pattern (#793)", () => {
  it("flags a query inside a for-of loop", () => {
    const text = `
      export async function loadAll(ids) {
        const out = [];
        for (const id of ids) {
          out.push(await prisma.note.findUnique({ where: { id } }));
        }
        return out;
      }
    `;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    const n1 = findings.filter((f) => f.taxonomy === "M7 — Prisma N+1 query pattern");
    expect(n1).toHaveLength(1);
    expect(n1[0]).toMatchObject({ severity: "Perf", precisionTier: "review" });
    expect(n1[0]?.title).toContain("prisma.note.findUnique");
  });

  it("flags a query inside a `.map` callback", () => {
    const text = `
      export const loadAll = (ids) => Promise.all(ids.map(async (id) => prisma.note.findUnique({ where: { id } })));
    `;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma N+1 query pattern")).toHaveLength(1);
  });

  it("stays silent on a single query whose result is then `.map`ped (not a query per iteration)", () => {
    const text = `
      export async function loadAll() {
        const notes = await prisma.note.findMany();
        return notes.map((n) => n.title);
      }
    `;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma N+1 query pattern")).toHaveLength(0);
  });

  it("stays silent on a query in an ordinary function with no enclosing loop", () => {
    const text = `export const getOne = (id) => prisma.note.findUnique({ where: { id } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma N+1 query pattern")).toHaveLength(0);
  });

  it("stays silent on a mutation-per-iteration loop (create/update have no Prisma bulk-conditional alternative)", () => {
    const text = `
      export async function seedAll(items) {
        for (const item of items) {
          await prisma.note.create({ data: item });
        }
      }
    `;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma N+1 query pattern")).toHaveLength(0);
  });

  it("does not fire on a same-shaped call on a non-Prisma-named object", () => {
    const text = `
      export async function loadAll(ids) {
        for (const id of ids) {
          await cache.note.findUnique({ where: { id } });
        }
      }
    `;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma N+1 query pattern")).toHaveLength(0);
  });
});

describe("prisma-app-perf filter-column-without-index (#793)", () => {
  it("flags a `where` filter on a scalar column with no covering index anywhere", () => {
    const text = `export const active = () => prisma.note.findMany({ where: { status: "active" } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    const filterFindings = findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index");
    expect(filterFindings).toHaveLength(1);
    expect(filterFindings[0]).toMatchObject({ severity: "Perf", precisionTier: "review" });
    expect(filterFindings[0]?.title).toContain("Note.status");
  });

  it("stays silent when the filtered column is covered by @@index", () => {
    const text = `export const forTenant = (tenantId) => prisma.note.findMany({ where: { tenantId } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index")).toHaveLength(0);
  });

  it("stays silent when the filtered column is covered by @unique", () => {
    const text = `export const byEmail = (email) => prisma.user.findFirst({ where: { email } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index")).toHaveLength(0);
  });

  it("stays silent on a filter by the primary key alone", () => {
    const text = `export const byId = (id) => prisma.note.findFirst({ where: { id } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index")).toHaveLength(0);
  });

  it("stays silent when a SIBLING filter key in the same where IS indexed (composite pruning likely applies)", () => {
    const text = `export const q = (tenantId) => prisma.note.findMany({ where: { tenantId, status: "active" } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index")).toHaveLength(0);
  });

  it("stays silent on a pure relation filter (no scalar key to check)", () => {
    const text = `export const q = (id) => prisma.note.findMany({ where: { user: { id } } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index")).toHaveLength(0);
  });

  it("stays silent on findUnique — its `where` is already guaranteed unique by Prisma's own types", () => {
    const text = `export const q = (status) => prisma.note.findUnique({ where: { status } });`;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index")).toHaveLength(0);
  });

  it("de-dupes repeated call sites filtering the same unindexed column into one finding", () => {
    const text = `
      export const a = () => prisma.note.findMany({ where: { status: "active" } });
      export const b = () => prisma.note.findMany({ where: { status: "archived" } });
    `;
    const findings = detectPrismaAppPerfFindings(file(text), schema);
    expect(findings.filter((f) => f.taxonomy === "M7 — Prisma filter column without index")).toHaveLength(1);
  });
});
