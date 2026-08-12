import type { Finding } from "../findings.js";
import { ORM_LABELS, type TargetOrm } from "./framework-detect.js";

function prismaArchitectureNote(): Finding {
  return {
    id: "M1-ARCH-PRISMA", title: "DB-level RLS checks not applicable — Prisma/Postgres architecture", severity: "Info", confidence: "N/A", category: "Multi-tenant isolation", taxonomy: "Architecture — Prisma/Postgres (no DB-level RLS)", location: "(repo-wide)", status: "Open",
    evidence: "Target detected as a Prisma/Postgres app (schema.prisma / @prisma/client) with no Supabase project. Supabase's Postgres RLS lives in supabase/migrations and is enforced by the database; a Prisma app has none of that surface, so the migration-RLS, PostgREST-exposure, and edge-config detectors have nothing to analyze.",
    impact: "Not a defect. Tenant isolation in a Prisma app is entirely app-layer — enforced in query code, not by the database — so it is assessed by the app-layer M1 detectors (pg-idor, bola-owner, pg-response-exposure, service-role-literal) and the LLM semantic pass, not by the RLS detectors. This row records that the DB-level RLS tier is N/A by architecture rather than leaving its absence unstated.",
    fix: "None required. Confirm every query is tenant-scoped in application code (the app-layer M1 detectors cover this).", value: 1, ease: 5, safety: 5, mechanical: true,
  };
}

function drizzleArchitectureNote(): Finding {
  return {
    id: "M1-ARCH-DRIZZLE", title: "DB-level RLS checks not applicable — Drizzle/Postgres architecture; tenant-scope partially assessed", severity: "Info", confidence: "N/A", category: "Multi-tenant isolation", taxonomy: "Architecture — Drizzle (no DB-level RLS; builder-chain tenant-scope detector runs)", location: "(repo-wide)", status: "Open",
    evidence: "Target's data layer detected as Drizzle with no Supabase project — there is no DB-level RLS surface (the migration-RLS, PostgREST-exposure and edge-config detectors read supabase/migrations, supabase/config.toml and supabase/functions, none of which exist here). The Drizzle tenant-scope detector (#901, drizzle-tenant-scope) DID run: it flags a db.select()/update()/delete() chain whose .where(...) filters by the primary key alone (eq(table.id, …)) with no tenant/owner column.",
    impact: "Mechanical tenant-scope coverage for this target is PARTIAL, not clean: the Drizzle query-builder chain is analysed, but the relational-query API (db.query.<table>.findFirst/findMany) and any raw-SQL escape hatch are NOT — a missing tenant predicate in those shapes would not be flagged. Coverage is therefore INCOMPLETE; recorded so the absence of further findings reads as \"partially assessed\" rather than \"assessed and clean\".",
    fix: "Review tenant scoping in the relational-query API and any raw-SQL access by hand (or with the paid LLM semantic pass, which is not ORM-shape-bound): every read and write must filter on the tenant/owner column, not on the primary key alone.", value: 1, ease: 5, safety: 5, mechanical: true,
  };
}

function unsupportedDataLayerNote(orm: Exclude<TargetOrm, "unknown" | "supabase" | "prisma" | "drizzle">): Finding {
  const label = ORM_LABELS[orm];
  const coveredShape = orm === "raw-sql"
    ? "The Express+`pg` app-layer detectors (pg-idor, pg-response-exposure) DID run and cover handlers written in that shape; queries issued from any other shape — a different HTTP framework, a hand-rolled query module — are matched by none of them."
    : `No detector matches ${label} query shapes: the app-layer M1 detectors that ran cover Express+\`pg\` call sites, Supabase service-role clients, the Prisma idiom (#760), and the Drizzle builder chain (#901) only.`;
  return {
    id: `M1-ARCH-${orm.toUpperCase()}`, title: `Tenant-scope checks not assessed — ${label} data layer`, severity: "Info", confidence: "N/A", category: "Multi-tenant isolation", taxonomy: `Architecture — ${label} (no DB-level RLS, no tenant-scope detector)`, location: "(repo-wide)", status: "Open",
    evidence: `Target's data layer detected as ${label} with no Supabase project. There is no DB-level RLS surface to analyse (the migration-RLS, PostgREST-exposure and edge-config detectors read supabase/migrations, supabase/config.toml and supabase/functions, none of which exist here), so tenant isolation is enforced entirely in application query code. ${coveredShape}`,
    impact: `Mechanical tenant-scope coverage for this target is INCOMPLETE, not clean: a missing tenant predicate in a ${label} query would not be flagged by this tier. Recorded so the absence of M1 tenant-scope findings reads as "not assessed here" rather than "assessed and clean".`,
    fix: `Review tenant scoping in the ${label} data-access layer by hand (or with the paid LLM semantic pass, which is not ORM-shape-bound): every read and write must filter on the tenant/owner column, not on the primary key alone.`, value: 1, ease: 5, safety: 5, mechanical: true,
  };
}

export function architectureFindings(orm: TargetOrm): Finding[] {
  if (orm === "prisma") return [prismaArchitectureNote()];
  if (orm === "drizzle") return [drizzleArchitectureNote()];
  if (orm !== "supabase" && orm !== "unknown") return [unsupportedDataLayerNote(orm)];
  return [];
}
