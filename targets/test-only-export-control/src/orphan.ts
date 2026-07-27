// PLANT — a whole module whose only importer is its own test: the shape src/fix/escalation.ts and
// src/fix/verify-harness.ts are in. knip reports the FILE, so the gate has to name the exports
// inside it or the capability stays invisible behind a path.

export function neverCalledInProduction(): number {
  return 2;
}

export const ORPHAN_LIMIT = 7;
