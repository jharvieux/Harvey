// #1503 — the row exists because a DISCONNECTED import graph produced no output at all, and the
// corpus then recorded the degraded numbers as the correct baselines. Both directions matter here:
// it has to FIRE on the shape that disconnected ghostfolio, and it has to be SILENT on a whole
// graph, or it degrades into a status line the family is explicitly not.

import { describe, expect, it } from "vitest";
import type { SourceInput } from "../detectors/common.js";
import type { Finding } from "../findings.js";
import { importGraphCensus, importGraphNotAssessedRows } from "./import-graph-scope.js";

const ids = (files: SourceInput[]) => importGraphNotAssessedRows(files).map((r) => r.id);
const only = (files: SourceInput[]): Finding => {
  const rows = importGraphNotAssessedRows(files);
  expect(rows).toHaveLength(1);
  return rows[0]!;
};

// The ghostfolio shape (#1479): an Nx monorepo whose `paths` map lives in `tsconfig.base.json`,
// with no root `tsconfig.json`. Here it is planted with the map in a file Harvey does NOT read
// (`vite.config.ts`), which reproduces the same end state — no declared alias — on a tree whose
// manifests plainly declare a workspace.
const nxUnread: SourceInput[] = [
  { path: "package.json", text: JSON.stringify({ name: "root", workspaces: ["apps/*", "libs/*"] }) },
  { path: "vite.config.ts", text: "export default { resolve: { alias: { '@myorg': './libs' } } };" },
  { path: "libs/util/package.json", text: JSON.stringify({ name: "@myorg/util", main: "./index.ts" }) },
  { path: "libs/util/index.ts", text: "export const u = 1;" },
  { path: "apps/api/src/main.ts", text: 'import { u } from "@myorg/nowhere";\n' },
];

describe("import-graph coverage disclosure (#1503)", () => {
  it("fires when no config declares an alias on a workspace target — the shape that disconnected ghostfolio", () => {
    const c = importGraphCensus(nxUnread);
    expect(c.builtInDefaultOnly).toBe(true);
    expect(c.workspaceImplied).toBe(true);
    expect(ids(nxUnread)).toEqual(["M1-IMPORTGRAPH-00"]);
    expect(only(nxUnread).evidence).toContain("built-in `@/` → repo-root default");
  });

  // The failing direction the whole family turns on: a target whose graph IS whole must produce
  // NOTHING. Without this, "the row is present" would mean nothing, and 5 of the 17 pinned corpus
  // targets are in exactly this state (MEASURED 2026-08-01: ghostfolio, cravab, launch-mvp,
  // multi-tenant-starter, supabase-security-labs emit no row).
  it("is silent when every repo-local specifier resolves", () => {
    const whole: SourceInput[] = [
      { path: "package.json", text: JSON.stringify({ name: "app", dependencies: { react: "^19" } }) },
      { path: "tsconfig.json", text: JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["./src/*"] } } }) },
      { path: "src/lib/db.ts", text: "export const db = 1;" },
      { path: "src/app/page.tsx", text: 'import { db } from "@/lib/db";\nimport React from "react";\nimport "./page.css";\nimport { readFile } from "node:fs/promises";\n' },
    ];
    const c = importGraphCensus(whole);
    expect(c.edgesResolved).toBe(1);
    expect(c.unresolvedRelative + c.unresolvedAliased).toBe(0);
    // A declared dependency, a stylesheet and a Node builtin are not dropped edges — if any were
    // counted the row would fire on every target alive and disclose nothing.
    expect(c.externalSpecifiers).toBe(2);
    expect(ids(whole)).toEqual([]);
  });

  it("is silent on an empty source set rather than reporting a graph nobody asked for", () => {
    expect(ids([])).toEqual([]);
  });

  it("counts a bare specifier no manifest declares, and names it", () => {
    const partial: SourceInput[] = [
      { path: "tsconfig.json", text: JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["./src/*"] } } }) },
      { path: "src/lib/db.ts", text: "export const db = 1;" },
      { path: "src/app/page.tsx", text: 'import { db } from "@/lib/db";\nimport { gen } from "@/generated/prisma/enums";\nimport { x } from "./absent";\n' },
    ];
    const c = importGraphCensus(partial);
    expect({ resolved: c.edgesResolved, alias: c.unresolvedAliased, relative: c.unresolvedRelative }).toEqual({ resolved: 1, alias: 1, relative: 1 });
    const row = only(partial);
    expect(row.evidence).toContain("2 import specifier(s) resolved to nothing");
    expect(row.evidence).toContain('src/app/page.tsx imports "@/generated/prisma/enums"');
    expect(row.title).toBe("Cross-file import graph partially resolved: 2 dropped edges of 3");
  });

  // The classifier's OWN failing direction, and #1503's defect reproduced one level in. Asking the
  // alias table "does this specifier look aliased?" is circular: when the table degrades, an
  // `@ghostfolio/common` specifier stops looking aliased and reads as a third-party package, so the
  // check goes quiet at exactly the moment it should shout. MEASURED with `collectPathAliases`
  // stubbed to its bare default over the real ghostfolio pin: an alias-table classifier reported
  // SILENT while 2,116 edges had vanished; the manifest-dependency yardstick reports 2,128 dropped.
  it("still sees a workspace specifier as repo-local when the alias table has degraded", () => {
    const degraded: SourceInput[] = [
      { path: "package.json", text: JSON.stringify({ name: "root", workspaces: ["libs/*"], dependencies: { react: "^19" } }) },
      // No tsconfig at all — the alias table is the bare fallback, so `@myorg/*` matches no prefix.
      { path: "libs/util/index.ts", text: "export const u = 1;" },
      { path: "apps/api/src/main.ts", text: 'import { u } from "@myorg/util";\nimport React from "react";\n' },
    ];
    const c = importGraphCensus(degraded);
    expect(c.builtInDefaultOnly).toBe(true);
    expect({ dropped: c.unresolvedAliased, external: c.externalSpecifiers }).toEqual({ dropped: 1, external: 1 });
    expect(ids(degraded)).toEqual(["M1-IMPORTGRAPH-00"]);
  });

  // A `virtual:` module, a Deno URL import and a data URL name something that is not a file, so the
  // filesystem graph is not missing an edge for them.
  it("does not count a non-filesystem specifier scheme as a dropped edge", () => {
    const schemes: SourceInput[] = [
      { path: "package.json", text: JSON.stringify({ name: "app" }) },
      { path: "server/app.ts", text: 'import b from "virtual:react-router/server-build";\nimport { serve } from "https://deno.land/std/http/server.ts";\n' },
    ];
    expect(importGraphCensus(schemes).unresolvedAliased).toBe(0);
    expect(ids(schemes)).toEqual([]);
  });

  // A TYPE-ONLY import is erased at compile time and buildImportGraph skips it (#1461), so counting
  // one as a dropped edge would report a limitation the graph does not have. Same predicate, both
  // places, or the census measures something other than the graph it describes.
  it("ignores a type-only import, exactly as buildImportGraph does", () => {
    const typeOnly: SourceInput[] = [
      { path: "tsconfig.json", text: JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["./src/*"] } } }) },
      { path: "src/app/page.tsx", text: 'import type { Row } from "@/types/absent";\n' },
    ];
    expect(importGraphCensus(typeOnly).unresolvedAliased).toBe(0);
    expect(ids(typeOnly)).toEqual([]);
  });

  // #1503's own lesson: the fallback row `collectPathAliases` pushes is byte-identical to a real
  // `"@/*": ["./*"]` alias declared with `baseUrl: "."`, so a shape test read proposit's genuine
  // alias as a degradation. It is marked at the push instead.
  it("does not read a genuine `@/*` -> repo-root alias as the built-in fallback", () => {
    const rootAlias: SourceInput[] = [
      { path: "package.json", text: JSON.stringify({ name: "root", workspaces: ["apps/*"] }) },
      { path: "tsconfig.json", text: JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["./*"] } } }) },
      { path: "components/card.tsx", text: "export const C = 1;" },
      { path: "app/page.tsx", text: 'import { C } from "@/components/card";\n' },
    ];
    const c = importGraphCensus(rootAlias);
    expect(c.builtInDefaultOnly).toBe(false);
    expect(ids(rootAlias)).toEqual([]);
  });
});
