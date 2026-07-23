// #761 (part of #756) M7 — static schema.prisma index review, the Prisma-schema equivalent of
// Supabase's connected-tier "unindexed foreign keys" performance advisor
// (LINT_PROFILES.unindexed_foreign_keys in src/perf-scan.ts). Postgres does not implicitly index a
// relation's scalar FK column the way Prisma's MySQL connector does — an index only exists when
// the schema explicitly declares one (@id/@unique on the field, or the field named in an
// @@id/@@unique/@@index list). An uncovered FK column means every JOIN through that relation and
// every cascade UPDATE/DELETE on the parent forces a sequential scan — the exact class
// unindexed_foreign_keys reports, derived here from schema.prisma alone (no live DB needed, so it
// runs on every Prisma engagement regardless of connected-tier access).
//
// Review tier, not high: schema.prisma is the current source of truth (not cumulative like
// migration files, so there's no "a later file already fixed this" caveat), but this still can't
// see an index created outside the schema (a raw `prisma db execute` migration) or confirm the
// datasource actually deploys to Postgres (the FK-index gap is Postgres-specific; MySQL doesn't
// have it). Conservative on coverage too: a field counts as indexed if it appears ANYWHERE in an
// @id/@unique attribute or an @@id/@@unique/@@index field list on its model — not only as the
// leading column of a composite key — so this under-reports a real but lower-value perf gap
// (non-leading composite position) rather than flagging a column the schema already indexes.
//
// Deliberately schema-only: app-code N+1 query patterns and "common filter column" analysis (an
// unindexed field read in a `where` elsewhere in the codebase) need cross-referencing app source,
// a materially less precise heuristic — split into #793 rather than risk a noisy first cut here.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

function stripLineComments(text: string): string {
  return text
    .split("\n")
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n");
}

// Mirrors src/prisma-schema-parse.ts's readBalancedBraces — Prisma model bodies don't nest
// braces, but staying depth-aware costs nothing and avoids a wrong truncation.
function readBalancedBraces(text: string, open: number): { body: string; end: number } | null {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}") {
      depth--;
      if (depth === 0) return { body: text.slice(open + 1, i), end: i };
    }
  }
  return null; // unterminated block — under-extract, don't guess where it ends
}

const MODEL_START = /\bmodel\s+(\w+)\s*\{/g;
const BLOCK_ATTR_LINE = /^\s*@@/;
const FIELD_LINE = /^\s*(\w+)\s+\w+(?:\?|\[\])?/;
// A field-level `@id`/`@unique` attribute — requires the literal token immediately after "@" and
// bounded by whitespace/`(`/end so "@id" can never match inside an unrelated attribute's text.
const idOrUniqueAttr = (attr: "id" | "unique") => new RegExp(`(^|\\s)@${attr}(\\s|\\(|$)`);
const ID_ATTR = idOrUniqueAttr("id");
const UNIQUE_ATTR = idOrUniqueAttr("unique");
// The scalar FK field(s) a relation field declares via `@relation(fields: [...], ...)`. Single-line
// only (matches the module's under-extract-rather-than-mis-extract convention) — a `@relation`
// attribute wrapped across multiple lines is skipped rather than guessed at.
const RELATION_FIELDS = /@relation\([^)]*\bfields:\s*\[([^\]]*)\]/;
// `@@id([...])` / `@@unique([...])` / `@@index([...])` field lists — any field named in one of
// these (in any position, see module header) counts as covered.
const BLOCK_COVERING_ATTR = /@@(?:id|unique|index)\(\s*\[([^\]]*)\]/g;

interface UnindexedFk {
  model: string;
  field: string;
  relationField: string;
  /** 1-based line number in the original schema text. */
  line: number;
}

/**
 * Scalar FK columns (the `fields: [...]` side of an `@relation`) with no covering index anywhere
 * on their model. Pure text analysis, unit-testable directly on schema.prisma content.
 */
export function findUnindexedForeignKeys(schema: string): UnindexedFk[] {
  const clean = stripLineComments(schema);
  const out: UnindexedFk[] = [];
  MODEL_START.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MODEL_START.exec(clean))) {
    const modelName = m[1]!;
    const open = clean.indexOf("{", m.index);
    const block = readBalancedBraces(clean, open);
    if (!block) break; // unterminated model block — nothing after it can be trusted either
    MODEL_START.lastIndex = block.end + 1;

    const covered = new Set<string>();
    for (const bm of block.body.matchAll(BLOCK_COVERING_ATTR)) {
      for (const raw of bm[1]!.split(",")) {
        const name = raw.trim().split(/[\s(]/)[0];
        if (name) covered.add(name);
      }
    }

    const fks = new Map<string, { relationField: string; line: number }>();
    let cursor = 0;
    for (const line of block.body.split("\n")) {
      const lineStart = open + 1 + cursor;
      cursor += line.length + 1; // +1 restores the '\n' the split() consumed
      if (BLOCK_ATTR_LINE.test(line)) continue; // @@map/@@index/@@id/… handled above, not a field
      const fm = FIELD_LINE.exec(line);
      if (!fm) continue;
      const fieldName = fm[1]!;
      if (ID_ATTR.test(line) || UNIQUE_ATTR.test(line)) covered.add(fieldName);
      const rm = RELATION_FIELDS.exec(line);
      if (!rm) continue;
      const lineNo = clean.slice(0, lineStart).split("\n").length;
      for (const raw of rm[1]!.split(",")) {
        const fkField = raw.trim();
        if (fkField) fks.set(fkField, { relationField: fieldName, line: lineNo });
      }
    }

    for (const [field, info] of fks) {
      if (!covered.has(field)) out.push({ model: modelName, field, relationField: info.relationField, line: info.line });
    }
  }
  return out;
}

function buildFinding(gap: UnindexedFk, schemaRelPath: string): Finding {
  return mechanicalFinding({
    id: `PRISMA-M7-UNINDEXED-FK-${gap.model}-${gap.field}`,
    title: `${gap.model}.${gap.field} — unindexed foreign key`,
    severity: "Perf",
    category: "Performance",
    taxonomy: "M7 — Prisma unindexed foreign key",
    location: `${schemaRelPath}:${gap.line} (${gap.model}.${gap.field})`,
    evidence: `\`${gap.model}.${gap.field}\` backs \`${gap.relationField}\`'s \`@relation(fields: [${gap.field}], …)\` with no covering index — no \`@unique\`/\`@id\` on the field, and no \`@@id\`/\`@@unique\`/\`@@index\` naming it on ${gap.model}. Postgres does not implicitly index a relation's scalar FK column (unlike Prisma's MySQL connector), so this is the schema-static equivalent of Supabase's unindexed_foreign_keys advisor lint.`,
    impact: "Sequential scans on parent UPDATE/DELETE and on every JOIN/lookup through this relation; degrades linearly as the table grows and is invisible until it doesn't fit in cache.",
    fix: `Add \`@@index([${gap.field}])\` on model ${gap.model} (or make the field \`@unique\` if the relation is one-to-one).`,
    precisionTier: "review",
  });
}

const PRISMA_SCHEMA_PATHS = ["schema.prisma", join("prisma", "schema.prisma")];

/** Locates the target's schema.prisma (same two conventional paths as detectOrm) and emits a
 * Finding per unindexed FK column. Empty when no schema.prisma is found. */
export function scanPrismaSchemaPerf(dir: string): Finding[] {
  const relPath = PRISMA_SCHEMA_PATHS.find((p) => existsSync(join(dir, p)));
  if (!relPath) return [];
  const schema = readFileSync(join(dir, relPath), "utf8");
  return findUnindexedForeignKeys(schema).map((gap) => buildFinding(gap, relPath));
}
