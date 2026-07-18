// #502 — the ordered execution plan for the out-of-orchestrator passes.
//
// run-audit runs the mechanical modules itself, but the flagship passes (M3 vitals, the M1 LLM
// semantic scan, M2 dynamic pen-test, M6 verdict, M7/M10 connected tiers) happen OUTSIDE the
// orchestrator process — operator/LLM/skill passes that leave a <module>.pass.json. Their ORDER is
// a real data dependency, not tribal knowledge: the M3 hotspot ranking has to exist before
// `scan-focus` can render the M1 semantic pass's hotspot-priority brief, which in turn has to exist
// before `/vuln-scan` runs — run them out of order and the flagship semantic pass silently degrades
// to un-prioritized (the ATC engagement did exactly this). This emits the correct sequence so an
// operator does not have to reconstruct it from CLAUDE.md's module table.

import type { EngagementEnv } from "./audit-coverage.js";

interface PlanStep {
  label: string; // short pass name (module + tier)
  command: string; // the concrete command / skill invocation
  // The prior step whose OUTPUT this one consumes — the dependency the ATC run violated. A step
  // with a dependsOn must never be started before that step's artifact exists.
  dependsOn?: string;
}

// The ordered plan for the passes the orchestrator cannot run itself. Steps in scope are gated by
// the engagement's env flags, but the ORDER between the ones present is fixed: M3 → scan-focus → M1
// semantic → triage is the chain #502 exists to protect.
export function buildExecutionPlan(env: EngagementEnv): PlanStep[] {
  const steps: PlanStep[] = [];

  // M3 first: its hotspot ranking is the prioritization input every downstream consumer reads
  // (the M1 focus brief, M6 --hotspots, and the cross-module enrichment of #515). vitals is an
  // external plugin (run, don't build) — capture the report where vitals is installed.
  steps.push({
    label: "M3 vitals (hotspot ranking)",
    command: "pnpm exec tsx src/cli/hotspot-scan.ts <target> --hotspots-out hotspots.txt --out M3.json",
  });

  if (env.llm) {
    // The chain #502 protects. scan-focus reads M3's hotspots.txt; /vuln-scan reads scan-focus's
    // brief. Each dependsOn is the ordering that, if violated, loses the hotspot priority silently.
    steps.push({
      label: "M1 semantic focus brief",
      command: "pnpm scan-focus hotspots.txt --out focus.md",
      dependsOn: "M3 vitals (hotspot ranking)",
    });
    steps.push({
      label: "M1 semantic (/vuln-scan → /triage)",
      command: "/vuln-scan --extra docs/scan-extras.txt --extra focus.md  →  /triage --fp-rules docs/fp-rules.txt",
      dependsOn: "M1 semantic focus brief",
    });
    steps.push({
      label: "M6 maintainability verdict",
      command: "pnpm simplify-scan <target> --hotspots hotspots.txt  →  record the reviewed verdict",
      dependsOn: "M3 vitals (hotspot ranking)",
    });
  }

  if (env.dynamic) {
    steps.push({ label: "M2 dynamic pen-test", command: "pnpm exec tsx src/cli/pentest.ts (against a stood-up two-tenant stack)" });
  }

  if (env.connected) {
    steps.push({ label: "M7 advisors (per DB)", command: "pnpm perf-scan <project-ref>  (once per enumerated Supabase project)" });
    steps.push({ label: "M10 live classification", command: "SUPABASE_DB_URL=… pnpm pii-classify" });
  }

  // Every out-of-orchestrator pass banks a durable artifact so a re-run of run-audit derives `ran`
  // from evidence rather than a flag (#416/#448).
  steps.push({
    label: "record + re-derive",
    command: "pnpm record-pass --module <Mn> … --out <artifacts-dir>  →  pnpm exec tsx src/cli/run-audit.ts <target> --artifacts-dir <artifacts-dir> --findings-out engagement.json",
  });

  return steps;
}

export function formatExecutionPlan(steps: PlanStep[]): string {
  const lines = [
    "Execution plan — out-of-orchestrator passes, in dependency order (#502):",
    "(the orchestrator ran the mechanical modules above; these passes run outside it)",
    "",
  ];
  steps.forEach((step, i) => {
    lines.push(`  ${i + 1}. ${step.label}`);
    lines.push(`       ${step.command}`);
    if (step.dependsOn) lines.push(`       runs after: ${step.dependsOn} — do NOT start before its output exists`);
  });
  return lines.join("\n");
}
