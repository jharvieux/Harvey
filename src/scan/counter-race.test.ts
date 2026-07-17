import { describe, expect, it } from "vitest";
import { detectCounterRaceFindings } from "./counter-race.js";

const RACE = "Non-atomic read-modify-write race condition";
const run = (text: string) => detectCounterRaceFindings([{ path: "pages/api/counter/increment.js", text }]);
const flagged = (text: string) => run(text).some((f) => f.taxonomy === RACE);

describe("detectCounterRaceFindings", () => {
  it("flags a select→arithmetic→update read-modify-write on one table", () => {
    const text = `
      const { data: current } = await admin.from("counters").select("value").eq("name", name).single();
      const next = (current?.value ?? 0) + 1;
      await admin.from("counters").update({ value: next }).eq("name", name);
    `;
    expect(flagged(text)).toBe(true);
  });

  it("does not flag an atomic RPC increment (no select-then-update pair)", () => {
    expect(flagged(`await admin.rpc("increment_counter", { p_name: name });`)).toBe(false);
  });

  // The nasty FP shape the issue names: a legitimate read-then-write where the written value is
  // NOT derived from the read. The dataflow gate (arithmetic-derived-from-the-read) must clear it.
  it("does not flag a read-then-write of an unrelated fresh value", () => {
    const text = `
      const { data: current } = await admin.from("counters").select("value").eq("name", name).single();
      if (!current) return;
      await admin.from("counters").update({ label: req.body.label }).eq("name", name);
    `;
    expect(flagged(text)).toBe(false);
  });

  it("does not flag a select and update on DIFFERENT tables", () => {
    const text = `
      const { data: current } = await admin.from("counters").select("value").single();
      const next = (current?.value ?? 0) + 1;
      await admin.from("audit").update({ value: next });
    `;
    expect(flagged(text)).toBe(false);
  });

  it("emits at review tier, never free-count", () => {
    const text = `
      const { data: current } = await admin.from("counters").select("value").single();
      await admin.from("counters").update({ value: (current?.value ?? 0) + 1 });
    `;
    const race = run(text).filter((f) => f.taxonomy === RACE);
    expect(race).toHaveLength(1);
    expect(race[0]?.precisionTier).toBe("review");
  });
});
