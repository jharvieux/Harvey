// #1230 / D-091 items 22, 10 and 24 — three retry-safety orderings. Each negative is the fix the
// corresponding finding recommends, so a rule that fired on one would be recommending its own
// false positive.

import { describe, expect, it } from "vitest";
import { detectIdempotencyFindings } from "./idempotency.js";

const scan = (text: string, path = "src/lib/jobs/reminders.ts") => detectIdempotencyFindings([{ path, text }]);

describe("claim-before-send (item 22)", () => {
  it("fires when the row is stamped after the send inside a loop", () => {
    const out = scan(`
      export async function fire(rows: Row[]) {
        for (const row of rows) {
          await sendReminder(row.recipient);
          await supabase.from("reminders").update({ sent_at: new Date().toISOString() }).eq("id", row.id);
        }
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Batch send stamped after dispatch instead of claimed before");
  });

  it("is silent when the CAS claim precedes the send", () => {
    expect(
      scan(`
        export async function fire(rows: Row[]) {
          for (const row of rows) {
            const { data: claimed } = await supabase.from("reminders").update({ sent_at: now() }).eq("id", row.id).is("sent_at", null).select("id");
            if (!claimed?.length) continue;
            await sendReminder(row.recipient);
          }
        }
      `),
    ).toEqual([]);
  });

  it("is silent for a stamp field that is not a send marker", () => {
    expect(
      scan(`
        export async function fire(rows: Row[]) {
          for (const row of rows) {
            await sendReminder(row.recipient);
            await supabase.from("reminders").update({ updated_at: now() }).eq("id", row.id);
          }
        }
      `),
    ).toEqual([]);
  });
});

describe("dedup-before-dispatch (item 10)", () => {
  it("fires when the idempotency row lands before the handler", () => {
    const out = scan(`
      export async function process(event: Event) {
        await supabase.from("webhook_events").insert({ event_id: event.id });
        await handleSubscriptionEvent(event);
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Idempotency row written before the dispatched handler");
  });

  it("is silent when the handler runs first", () => {
    expect(
      scan(`
        export async function process(event: Event) {
          await handleSubscriptionEvent(event);
          await supabase.from("webhook_events").insert({ event_id: event.id });
        }
      `),
    ).toEqual([]);
  });

  it("is scoped to one function — an unrelated handler call further down the file is not the bug", () => {
    expect(
      scan(`
        export async function record(event: Event) {
          await supabase.from("webhook_events").insert({ event_id: event.id });
        }
        export async function replay(event: Event) {
          await handleSubscriptionEvent(event);
        }
      `),
    ).toEqual([]);
  });

  it("is silent on an insert into a table that is not a dedup ledger", () => {
    expect(
      scan(`
        export async function process(event: Event) {
          await supabase.from("invoices").insert({ event_id: event.id });
          await handleSubscriptionEvent(event);
        }
      `),
    ).toEqual([]);
  });
});

describe("external-send idempotency key (item 24)", () => {
  it("fires on a Stripe create with no request options, from a retryable path", () => {
    const out = scan(`export const charge = (stripe: Stripe, id: string) => stripe.paymentIntents.create({ amount: 100, metadata: { id } });`);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("External send without a deterministic idempotency key");
  });

  it("fires on a REST call to a known idempotent host with no key header", () => {
    expect(
      scan(`export const notify = (p: unknown) => fetch("https://api.resend.com/emails", { method: "POST", body: JSON.stringify(p) });`),
    ).toHaveLength(1);
  });

  it("is silent when the key is present in either form", () => {
    expect(
      scan(`
        export const charge = (stripe: Stripe, id: string) =>
          stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: \`charge:\${id}\` });
        export const notify = (p: unknown, id: string) =>
          fetch("https://api.resend.com/emails", { method: "POST", headers: { "Idempotency-Key": id }, body: JSON.stringify(p) });
      `),
    ).toEqual([]);
  });

  it("is silent outside a retryable path — the platform, not the user, is what makes a retry likely", () => {
    expect(
      scan(
        `export const charge = (stripe: Stripe, id: string) => stripe.paymentIntents.create({ amount: 100, metadata: { id } });`,
        "src/components/CheckoutButton.tsx",
      ),
    ).toEqual([]);
  });

  it("is silent for a host whose idempotency contract we cannot name", () => {
    expect(
      scan(`export const notify = (p: unknown) => fetch("https://api.acme.example/send", { method: "POST", body: JSON.stringify(p) });`),
    ).toEqual([]);
  });
});
