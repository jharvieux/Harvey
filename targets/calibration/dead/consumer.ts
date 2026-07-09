// dead/consumer.ts — knip entry point. Imports orphan.ts's live export so
// the file itself isn't flagged as dead, isolating the M5-P-DEAD-EXPORT
// signal to the specific unused export in orphan.ts.
import { computeTotal } from "./orphan";

export function reportTotal(a: number, b: number): number {
  return computeTotal(a, b);
}
