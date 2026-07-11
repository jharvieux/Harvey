// Audit module-coverage gate. The audit is a 9-module product (M1–M9); a delivery is only
// "complete" when EVERY module is accounted for — either run, or explicitly marked not-applicable
// with a reason. This is the same completeness discipline as the target gate (src/pentest/
// targets.ts): the RAG-backend and the M8/test-health omissions both happened because nothing
// mechanically checked that everything ran. assertModuleCoverage fails loud on any module left in
// an unaccounted (skipped/missing) state, so a module can't be silently dropped from an engagement.

type ModuleNeed = "source" | "connected" | "dynamic" | "llm";

interface AuditModule {
  id: string; // M1..M9
  name: string;
  tools: string; // what runs it
  needs: ModuleNeed; // the minimum environment it requires
  freeTier: boolean; // contributes to the free quick-scan (vs paid-only)
}

// The canonical 9 modules (docs/audit-modules.md / epic #2). `needs` lets the gate tell a
// legitimate environment-gated skip (e.g. M7 with no live DB in scope) from a silent omission —
// but even a legitimate skip must be RECORDED as "na" with a reason, never just left out.
export const AUDIT_MODULES: AuditModule[] = [
  { id: "M1", name: "Multi-tenant security", tools: "D-091 guards + scan-extras + Supabase security advisor + Semgrep", needs: "source", freeTier: true },
  { id: "M2", name: "Local pen test (dynamic)", tools: "seeded target + probe kit (src/pentest)", needs: "dynamic", freeTier: false },
  { id: "M3", name: "Hotspots", tools: "vitals (churn × complexity)", needs: "source", freeTier: false },
  { id: "M4", name: "Duplication", tools: "jscpd", needs: "source", freeTier: true },
  { id: "M5", name: "Slop / dead code", tools: "knip", needs: "source", freeTier: false },
  { id: "M6", name: "Simplification / reuse", tools: "/simplify + quality-extras (LLM)", needs: "llm", freeTier: false },
  { id: "M7", name: "Performance", tools: "Supabase performance advisor", needs: "connected", freeTier: false },
  { id: "M8", name: "Test quality", tools: "Stryker mutation testing", needs: "source", freeTier: true },
  { id: "M9", name: "Next.js App Router", tools: "scan-extras M9 + detectors", needs: "source", freeTier: true },
];

type ModuleStatus = "ran" | "na" | "skipped";

export interface ModuleRecord {
  status: ModuleStatus; // "ran" = executed (even if the result was "no tests exist"); "na" = deliberately not applicable; "skipped" = left undone
  note?: string; // required for "na" — why it doesn't apply (e.g. "no live DB in engagement scope")
}

// Which environments the engagement actually has. A module whose `needs` isn't available is only
// allowed to be "na", and still must carry a reason — this is what turns "we didn't have a live
// DB" into a recorded decision instead of a silent gap.
interface EngagementEnv {
  connected: boolean; // a live/read-only database was provided
  dynamic: boolean; // a running app / self-hosted clone is available for probing
  llm: boolean; // the paid LLM tier is in scope
}

interface ModuleCoverage {
  complete: boolean;
  ran: string[];
  na: { id: string; note: string }[];
  gaps: string[]; // modules neither run nor validly marked na — the fail-loud set
}

export function assessModuleCoverage(records: Record<string, ModuleRecord>, env?: EngagementEnv): ModuleCoverage {
  const ran: string[] = [];
  const na: { id: string; note: string }[] = [];
  const gaps: string[] = [];
  for (const mod of AUDIT_MODULES) {
    const rec = records[mod.id];
    if (rec?.status === "ran") {
      ran.push(mod.id);
    } else if (rec?.status === "na" && rec.note?.trim()) {
      na.push({ id: mod.id, note: rec.note.trim() });
    } else {
      // Missing, "skipped", or "na" without a reason → a gap. Annotate the likely cause.
      const envGated = env && ((mod.needs === "connected" && !env.connected) || (mod.needs === "dynamic" && !env.dynamic) || (mod.needs === "llm" && !env.llm));
      gaps.push(envGated ? `${mod.id} (needs ${mod.needs}: mark na with a reason)` : mod.id);
    }
  }
  return { complete: gaps.length === 0, ran, na, gaps };
}

export function assertModuleCoverage(records: Record<string, ModuleRecord>, env?: EngagementEnv): void {
  const { complete, gaps } = assessModuleCoverage(records, env);
  if (!complete) {
    throw new Error(`Incomplete audit-module coverage — ${gaps.length} module(s) unaccounted: ${gaps.join(", ")}. Every module must be run or marked na with a reason before delivery.`);
  }
}
