// #1230 / D-091 item 6 — an allowance read once and consumed across a loop without re-reading.
// The running-total negative is the shipping condition: a rule keyed on "a limit-ish name compared
// inside a loop" fires on every bounded loop in every codebase, and requiring the guard value to be
// bound from a DB read is what clears it.

import { describe, expect, it } from "vitest";
import { detectStaleQuotaReadFindings } from "./stale-quota-read.js";

const scan = (text: string, path = "src/lib/cron/batches.ts") => detectStaleQuotaReadFindings([{ path, text }]);

describe("stale-quota-read — fires on a DB-read allowance consumed across a loop", () => {
  it("catches the read-once, spend-many gate", () => {
    const out = scan(`
      export async function run(tenantId: string, batches: string[]) {
        const { data: budget } = await supabase.from("budgets").select("remaining_cents").eq("tenant_id", tenantId).single();
        for (const batch of batches) {
          if ((budget?.remaining_cents ?? 0) < 100) break;
          await runBatch(batch);
        }
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Quota gate consumed across a loop without re-reading");
    expect(out[0]!.precisionTier).toBe("review");
  });

  it("catches it in a while loop too", () => {
    expect(
      scan(`
        export async function drain(tenantId: string) {
          const { data: quota } = await supabase.from("quotas").select("left").eq("tenant_id", tenantId).single();
          while (quota.left > 0) {
            await consumeOne();
          }
        }
      `),
    ).toHaveLength(1);
  });
});

describe("stale-quota-read — silent on the shapes that are not stale", () => {
  it("is silent when the loop re-reads the allowance", () => {
    expect(
      scan(`
        export async function run(tenantId: string, batches: string[]) {
          for (const batch of batches) {
            const { data: budget } = await supabase.from("budgets").select("remaining_cents").eq("tenant_id", tenantId).single();
            if ((budget?.remaining_cents ?? 0) < 100) break;
            await runBatch(batch);
          }
        }
      `),
    ).toEqual([]);
  });

  it("is silent on a running total compared against a constant ceiling", () => {
    expect(
      scan(`
        export async function run(batches: string[]) {
          let spentCents = 0;
          for (const batch of batches) {
            if (spentCents > 10000) break;
            spentCents += await runBatch(batch);
          }
        }
      `),
    ).toEqual([]);
  });

  it("is silent when the loop consumes nothing", () => {
    expect(
      scan(`
        export async function summarise(tenantId: string, batches: string[]) {
          const { data: budget } = await supabase.from("budgets").select("remaining_cents").eq("tenant_id", tenantId).single();
          const affordable = batches.filter(() => (budget?.remaining_cents ?? 0) > 100);
          return affordable.length;
        }
      `),
    ).toEqual([]);
  });
});
