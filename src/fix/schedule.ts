// Batching + parallel scheduling + merge-order emission (design §1.3/§4). This is the REAL caller of
// pipeline.ts `batch()` — until now `batch()` existed only in its own test. It turns a set of eligible
// fixes into: file-overlap conflict components that serialize internally (severity desc, then BFTB
// desc), an ordering of those components (highest contained severity first), a concurrency scheduler
// that overlaps independent components up to the caps, a late-conflict detector for the pre-push check,
// and a client-facing merge-order advisory. Everything here is advice + scheduling, never a merge:
// Harvey never merges (§1.5).

import type { Severity } from "../findings.js";
import type { FixPlan } from "./plan.js";
import { batch } from "./pipeline.js";

// One node the scheduler reasons over: a fix's identity, how urgent it is (severity + BFTB), and the
// files its diff touches (blastRadius.files ∪ createdFiles) — the overlap key that decides conflicts.
export interface ScheduleNode {
  findingId: string;
  severity: Severity;
  bftb: number; // value·ease·safety — higher fixes first within a severity band
  files: string[];
}

interface ScheduledComponent {
  findingIds: string[]; // serialized order WITHIN the component (severity desc, BFTB desc)
  topSeverity: Severity; // highest severity contained — orders components against each other
}

const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 6, High: 5, Medium: 4, Low: 3, Perf: 2, Info: 1, Watch: 0,
};

// severity desc, then BFTB desc, then id asc so the order is total and stable.
function compareNodes(a: ScheduleNode, b: ScheduleNode): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.bftb - a.bftb || a.findingId.localeCompare(b.findingId);
}

function planOf(n: ScheduleNode): Pick<FixPlan, "findingId" | "blastRadius"> {
  return {
    findingId: n.findingId,
    blastRadius: { files: n.files, createdFiles: [], symbols: [], callers: [], behaviorPreserving: true, estimatedChangedLines: 0 },
  };
}

// batch() → conflict components; each is ordered internally, then the components are ordered by their
// highest contained severity (tie broken by the top node's BFTB). Independent components can run in
// parallel (§1.3); the order here is the SERIAL fallback / merge-priority order.
export function scheduleFixes(nodes: ScheduleNode[]): ScheduledComponent[] {
  const byId = new Map(nodes.map((n) => [n.findingId, n]));
  const components = batch(nodes.map(planOf)).map((ids): ScheduledComponent => {
    const ordered = ids.map((id) => byId.get(id)).filter((n): n is ScheduleNode => n !== undefined).sort(compareNodes);
    return { findingIds: ordered.map((n) => n.findingId), topSeverity: ordered[0]?.severity ?? "Watch" };
  });
  return components.sort((x, y) => {
    const sev = SEVERITY_RANK[y.topSeverity] - SEVERITY_RANK[x.topSeverity];
    if (sev !== 0) return sev;
    const bx = byId.get(x.findingIds[0] as string)?.bftb ?? 0;
    const by = byId.get(y.findingIds[0] as string)?.bftb ?? 0;
    return by - bx || (x.findingIds[0] as string).localeCompare(y.findingIds[0] as string);
  });
}

export interface MergeOrder {
  order: string[]; // flat finding-id order across all components — the recommended merge sequence
  notes: string[]; // "PRs for A and B touch <file>; merge A first, then re-run CI on B" (§4)
}

// The client-facing merge advisory (§4). Order is components in priority order, findings serialized
// within each; a note is emitted for every within-component file overlap so the client knows exactly
// why two PRs are sequenced and which to merge first. PRs are always cut against the default branch,
// never stacked — this is advice, not automation (§1.5).
export function emitMergeOrder(components: ScheduledComponent[], nodes: ScheduleNode[]): MergeOrder {
  const filesOf = new Map(nodes.map((n) => [n.findingId, new Set(n.files)]));
  const order: string[] = [];
  const notes: string[] = [];
  for (const comp of components) {
    order.push(...comp.findingIds);
    for (let i = 1; i < comp.findingIds.length; i++) {
      const later = comp.findingIds[i] as string;
      for (let j = 0; j < i; j++) {
        const earlier = comp.findingIds[j] as string;
        const shared = [...(filesOf.get(later) ?? [])].filter((f) => filesOf.get(earlier)?.has(f));
        if (shared.length) {
          notes.push(`PRs for ${earlier} and ${later} touch ${shared[0]}; merge ${earlier} first, then re-run CI on ${later}.`);
          break; // one note per later fix — its nearest earlier overlap
        }
      }
    }
  }
  return { order, notes };
}

// The pre-push dynamic conflict check (§4): before pushing a completed fix, its changed-file set is
// diffed against every already-pushed fix branch. Any overlap is returned so the caller re-queues the
// later fix to run serially after the earlier PR's disposition — batch-time overlap catches most, this
// catches the rest (a fix that grew a new file mid-implementation).
interface PushedBranch {
  findingId: string;
  changedFiles: string[];
}

export function detectLateConflict(changedFiles: string[], pushed: PushedBranch[]): { findingId: string; files: string[] }[] {
  const set = new Set(changedFiles);
  return pushed
    .map((p) => ({ findingId: p.findingId, files: p.changedFiles.filter((f) => set.has(f)) }))
    .filter((o) => o.files.length > 0);
}

// §4 concurrency caps: default 4 implement/verify slots overlap freely, but at most 2 full client-check
// runs at once so timings stay honest. These are ENFORCED here (a semaphore), not documented.
interface ConcurrencyCaps {
  maxSlots: number; // concurrent implement/verify slots
  maxClientChecks: number; // concurrent full client-check runs (the scarce resource)
}

export const DEFAULT_CAPS: ConcurrencyCaps = { maxSlots: 4, maxClientChecks: 2 };

class Semaphore {
  private available: number;
  private readonly queue: (() => void)[] = [];
  constructor(count: number) {
    this.available = count;
  }
  async acquire(): Promise<void> {
    if (this.available > 0) {
      this.available--;
      return;
    }
    await new Promise<void>((resolve) => this.queue.push(resolve));
  }
  release(): void {
    const next = this.queue.shift();
    if (next) next();
    else this.available++;
  }
}

// The client-check gate a worker must wrap its full-check phase in, so implement/verify overlaps up to
// maxSlots while client checks stay under maxClientChecks.
type ClientCheckGate = <R>(fn: () => Promise<R>) => Promise<R>;
type ComponentWorker<T> = (component: ScheduledComponent, clientCheck: ClientCheckGate) => Promise<T>;

export async function runScheduled<T>(
  components: ScheduledComponent[],
  worker: ComponentWorker<T>,
  caps: ConcurrencyCaps = DEFAULT_CAPS,
): Promise<T[]> {
  const slots = new Semaphore(caps.maxSlots);
  const checks = new Semaphore(caps.maxClientChecks);
  const clientCheck: ClientCheckGate = async (fn) => {
    await checks.acquire();
    try {
      return await fn();
    } finally {
      checks.release();
    }
  };
  return Promise.all(
    components.map(async (component) => {
      await slots.acquire();
      try {
        return await worker(component, clientCheck);
      } finally {
        slots.release();
      }
    }),
  );
}
