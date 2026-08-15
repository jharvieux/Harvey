// #1230 / D-091 items 22, 10 and 24 — three retry-safety orderings. Each negative is the fix the
// corresponding finding recommends, so a rule that fired on one would be recommending its own
// false positive.

import { describe, expect, it } from "vitest";
import { detectIdempotencyFindings } from "./idempotency.js";
import { MECHANICAL_DETECTORS } from "./mechanical-detector-registry.js";

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
  const expectSingleReview = (text: string, path?: string) => {
    const out = scan(text, path);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Idempotency key does not identify a stable scoped operation");
    expect(out[0]!.precisionTier).toBe("review");
    expect(out[0]!.evidence).toContain("FALSIFIER:");
    expect(out[0]!.evidence.length).toBeLessThan(1_600);
    return out[0]!;
  };

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
          fetch("https://api.resend.com/emails", { method: "POST", headers: { "Idempotency-Key": \`notify:\${id}\` }, body: JSON.stringify(p) });
      `),
    ).toEqual([]);
  });

  it.each([
    ["random-per-attempt", "crypto.randomUUID()"],
    ["random-per-attempt", "Math.random().toString(36)"],
    ["clock-or-attempt-derived", "`charge:${bookingId}:${Date.now()}`"],
    ["unsafe-global-constant", '"all-charges"'],
  ])("flags a %s key", (classification, expression) => {
    const out = scan(`
      export const charge = (stripe: Stripe, bookingId: string) =>
        stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: ${expression} });
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Idempotency key does not identify a stable scoped operation");
    expect(out[0]!.evidence).toContain(classification);
    expect(out[0]!.evidence).toContain("FALSIFIER:");
    expect(out[0]!.precisionTier).toBe("review");
  });

  it("requires the available tenant identity in a multi-tenant operation key", () => {
    const out = scan(`
      export const charge = (stripe: Stripe, tenantId: string, bookingId: string) =>
        stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: \`charge:\${bookingId}:v1\` });
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("missing-tenant-scope");
    expect(out[0]!.evidence).toContain("same entity identifier in two tenants");
  });

  it.each([
    ["missing-operation-scope", "bookingId"],
    ["missing-entity-scope", "`charge:${amountCents}`"],
  ])("flags %s instead of accepting token presence", (classification, expression) => {
    const out = scan(`
      export const charge = (stripe: Stripe, bookingId: string, amountCents: number) =>
        stripe.paymentIntents.create({ amount: amountCents }, { idempotencyKey: ${expression} });
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain(classification);
  });

  it("does not accept idempotency-looking metadata outside Stripe's real option slot", () => {
    const out = scan(`
      export const charge = (stripe: Stripe, bookingId: string) =>
        stripe.paymentIntents.create({ amount: 100 }, { metadata: { idempotencyNote: bookingId } });
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("External send without a deterministic idempotency key");
    expect(out[0]!.evidence).toContain("Unrelated idempotency-looking metadata");
  });

  it("emits a bounded review finding when a helper hides key semantics", () => {
    const out = scan(`
      declare function makeProviderKey(tenantId: string, bookingId: string, operation: string): string;
      export const charge = (stripe: Stripe, tenantId: string, bookingId: string) =>
        stripe.paymentIntents.create(
          { amount: 100 },
          { idempotencyKey: makeProviderKey(tenantId, bookingId, "charge") },
        );
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("mechanically-unproven-key-helper");
    expect(out[0]!.evidence).toContain("THIS FILE only");
    expect(out[0]!.evidence).toContain("FALSIFIER:");
  });

  it("does not resolve Stripe options from a sibling function's same-named local", () => {
    const out = scan(`
      function prepareOptions(tenantId: string, bookingId: string) {
        const options = { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` };
        return options;
      }

      export const charge = (
        stripe: Stripe,
        bookingId: string,
        options: Stripe.RequestOptions,
      ) => stripe.paymentIntents.create({ amount: 100 }, options);
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("the Stripe request-options expression is not a local object literal");
    expect(out[0]!.evidence).toContain("local provider options in THIS FILE only");
    expect(out[0]!.evidence).toContain("FALSIFIER:");
  });

  it.each([
    [
      "constructor parameter",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        class Billing {
          constructor(stripe: Stripe, options: Stripe.RequestOptions) {
            stripe.paymentIntents.create({ amount: 100 }, options);
          }
        }
      `,
      "parameter binding",
    ],
    [
      "setter parameter",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        class Billing {
          set charge(options: Stripe.RequestOptions) {
            stripe.paymentIntents.create({ amount: 100 }, options);
          }
        }
      `,
      "parameter binding",
    ],
    [
      "getter-local opaque options",
      `
        class Billing {
          get charge() {
            const options = this.providerOptions;
            return stripe.paymentIntents.create({ amount: 100 }, options);
          }
        }
      `,
      "expression is not a local object literal",
    ],
  ])("stops at a %s binding instead of borrowing an outer initializer", (_name, source, evidence) => {
    expect(expectSingleReview(source).evidence).toContain(evidence);
  });

  it("recognizes constructor and setter parameter identities, including destructuring", () => {
    expect(
      scan(`
        class Billing {
          constructor(stripe: Stripe, tenantId: string, bookingId: string) {
            stripe.paymentIntents.create(
              { amount: 100 },
              { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` },
            );
          }
          set receipt({ tenantId, bookingId }: { tenantId: string; bookingId: string }) {
            fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: { "Idempotency-Key": \`receipt:\${tenantId}:\${bookingId}:v1\` },
            });
          }
        }
      `),
    ).toEqual([]);
  });

  it("keeps namespace-local consts out of SourceFile lookup", () => {
    const finding = expectSingleReview(`
      namespace Defaults {
        export const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
      }
      export function charge(stripe: Stripe) {
        stripe.paymentIntents.create({ amount: 100 }, options);
      }
    `);
    expect(finding.evidence).toContain("no visible local binding");
  });

  it("lets a namespace import block a safe outer initializer", () => {
    const finding = expectSingleReview(`
      const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
      namespace Billing {
        import options = Provider.options;
        export function charge(stripe: Stripe) {
          stripe.paymentIntents.create({ amount: 100 }, options);
        }
      }
    `);
    expect(finding.evidence).toContain("import binding");
  });

  it("keeps a SourceFile import opaque even when a namespace has a safe same-named const", () => {
    const finding = expectSingleReview(`
      import { options } from "./provider-options";
      namespace Defaults {
        export const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
      }
      export function charge(stripe: Stripe) {
        stripe.paymentIntents.create({ amount: 100 }, options);
      }
    `);
    expect(finding.evidence).toContain("import binding");
  });

  it("accepts a function-local const inside a namespace without crossing the module boundary", () => {
    expect(
      scan(`
        namespace Billing {
          export function charge(stripe: Stripe, tenantId: string, bookingId: string) {
            const options = { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` };
            stripe.paymentIntents.create({ amount: 100 }, options);
          }
        }
      `),
    ).toEqual([]);
  });

  it.each([
    [
      "class static block var",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        class Billing {
          static {
            var options;
            stripe.paymentIntents.create({ amount: 100 }, options);
          }
        }
      `,
      "mutable or resource-managed",
    ],
    [
      "named function-expression self binding",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        const run = function options(stripe: Stripe) {
          stripe.paymentIntents.create({ amount: 100 }, options);
        };
      `,
      "function-self binding",
    ],
    [
      "named class-expression self binding",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        const Billing = class options {
          static run(stripe: Stripe) {
            stripe.paymentIntents.create({ amount: 100 }, options);
          }
        };
      `,
      "class-self binding",
    ],
    [
      "enum-member binding",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        enum Attempts {
          options = 1,
          charge = stripe.paymentIntents.create({ amount: 100 }, options) as any,
        }
      `,
      "enum-member binding",
    ],
  ])("does not fall through a %s to a same-spelled outer const", (_name, source, evidence) => {
    expect(expectSingleReview(source).evidence).toContain(evidence);
  });

  it("requires switch aliases to dominate in the same clause", () => {
    const finding = expectSingleReview(`
      const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
      switch (kind) {
        case "prepare":
          const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
          break;
        case "charge":
          stripe.paymentIntents.create({ amount: 100 }, options);
          break;
      }
    `);
    expect(finding.evidence).toContain("same switch clause");
  });

  it("accepts a switch alias declared earlier in the same clause", () => {
    expect(
      scan(`
        function charge(stripe: Stripe, tenantId: string, bookingId: string, kind: string) {
          switch (kind) {
            case "charge":
              const options = { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` };
              stripe.paymentIntents.create({ amount: 100 }, options);
              break;
          }
        }
      `),
    ).toEqual([]);
  });

  it("accepts an outer const that dominates the whole switch", () => {
    expect(
      scan(`
        function charge(stripe: Stripe, tenantId: string, bookingId: string, kind: string) {
          const options = { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` };
          switch (kind) {
            case "charge":
              stripe.paymentIntents.create({ amount: 100 }, options);
              break;
          }
        }
      `),
    ).toEqual([]);
  });

  it.each([
    [
      "let alias",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        {
          let options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
          stripe.paymentIntents.create({ amount: 100 }, options);
        }
      `,
      "mutable or resource-managed",
    ],
    [
      "property-reassigned const alias",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        options.idempotencyKey = nextKey;
        stripe.paymentIntents.create({ amount: 100 }, options);
      `,
      "mutated or escapes",
    ],
    [
      "conditionally initialized const alias",
      `
        const options = enabled
          ? { idempotencyKey: "charge:tenant_1:booking_1:v1" }
          : { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        stripe.paymentIntents.create({ amount: 100 }, options);
      `,
      "conditionally evaluated",
    ],
    [
      "escaped object alias",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        configure(options);
        stripe.paymentIntents.create({ amount: 100 }, options);
      `,
      "mutated or escapes",
    ],
    [
      "using alias",
      `
        using options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        stripe.paymentIntents.create({ amount: 100 }, options);
      `,
      "mutable or resource-managed",
    ],
    [
      "duplicate const binding",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        const options = { idempotencyKey: "charge:tenant_2:booking_2:v1" };
        stripe.paymentIntents.create({ amount: 100 }, options);
      `,
      "contains 2 declarations",
    ],
  ])("reviews a %s instead of claiming safety", (_name, source, evidence) => {
    expect(expectSingleReview(source).evidence).toContain(evidence);
  });

  it("reviews a reassigned primitive key alias", () => {
    const finding = expectSingleReview(`
      function charge(stripe: Stripe, tenantId: string, bookingId: string) {
        const key = \`charge:\${tenantId}:\${bookingId}:v1\`;
        key = nextKey;
        stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: key });
      }
    `);
    expect(finding.evidence).toContain("mutated or escapes");
  });

  it.each([
    [
      "same-scope TDZ const",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        {
          stripe.paymentIntents.create({ amount: 100 }, options);
          const options = opaqueOptions;
        }
      `,
    ],
    [
      "hoisted function declaration",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        {
          stripe.paymentIntents.create({ amount: 100 }, options);
          function options() {}
        }
      `,
    ],
    [
      "class TDZ declaration",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        {
          stripe.paymentIntents.create({ amount: 100 }, options);
          class options {}
        }
      `,
    ],
  ])("stops at a %s rather than using the latest prior initializer", (_name, source) => {
    expectSingleReview(source);
  });

  it.each([
    [
      "destructured parameter",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        function charge(stripe: Stripe, { options }: { options: Stripe.RequestOptions }) {
          stripe.paymentIntents.create({ amount: 100 }, options);
        }
      `,
      "parameter binding",
    ],
    [
      "destructured local",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        {
          const { options } = config;
          stripe.paymentIntents.create({ amount: 100 }, options);
        }
      `,
      "not a simple local const",
    ],
    [
      "destructured for-of binding",
      `
        const options = { idempotencyKey: "charge:tenant_1:booking_1:v1" };
        for (const { options } of requests) {
          stripe.paymentIntents.create({ amount: 100 }, options);
        }
      `,
      "not a simple local const",
    ],
  ])("treats a %s as opaque and never falls outward", (_name, source, evidence) => {
    expect(expectSingleReview(source).evidence).toContain(evidence);
  });

  it.each([
    ["random-per-attempt", "const suffix = crypto.randomUUID();"],
    ["clock-or-attempt-derived", "const suffix = Date.now();"],
  ])("expands a nested alias and classifies its %s suffix", (classification, declaration) => {
    const finding = expectSingleReview(`
      function charge(stripe: Stripe, tenantId: string, bookingId: string) {
        ${declaration}
        const key = \`charge:\${tenantId}:\${bookingId}:\${suffix}\`;
        stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: key });
      }
    `);
    expect(finding.evidence).toContain(classification);
  });

  it("expands nested aliases without trusting an opaque helper", () => {
    const finding = expectSingleReview(`
      function charge(stripe: Stripe, tenantId: string, bookingId: string) {
        const suffix = makeSuffix(bookingId);
        const key = \`charge:\${tenantId}:\${bookingId}:\${suffix}\`;
        stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: key });
      }
    `);
    expect(finding.evidence).toContain("mechanically-unproven-key-helper");
  });

  it("tracks recursive aliases by declaration identity", () => {
    const finding = expectSingleReview(`
      function charge(stripe: Stripe, tenantId: string, bookingId: string) {
        const key = key;
        stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: key });
      }
    `);
    expect(finding.evidence).toContain("cyclic");
  });

  it("does not count same-spelled tenant/entity shadow constants as parameter identity", () => {
    expectSingleReview(`
      function charge(stripe: Stripe, tenantId: string, bookingId: string) {
        {
          const tenantId = "fixed-tenant";
          const bookingId = "fixed-booking";
          stripe.paymentIntents.create(
            { amount: 100 },
            { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` },
          );
        }
      }
    `);
  });

  it("accepts transitive immutable aliases derived from the actual parameters", () => {
    expect(
      scan(`
        function charge(stripe: Stripe, tenantId: string, bookingId: string) {
          const tenant = tenantId;
          const entity = bookingId;
          const key = \`charge:\${tenant}:\${entity}:v1\`;
          stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: key });
        }
      `),
    ).toEqual([]);
  });

  it("rejects a key alias captured across a nested function boundary", () => {
    const finding = expectSingleReview(`
      function schedule(stripe: Stripe, tenantId: string, bookingId: string) {
        const key = \`charge:\${tenantId}:\${bookingId}:v1\`;
        return () => stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: key });
      }
    `);
    expect(finding.evidence).toContain("crosses an eager-execution/function boundary");
  });

  it("treats JavaScript with as dynamically scoped before inspecting otherwise-safe options", () => {
    const finding = expectSingleReview(
      `
        function charge(stripe, tenantId, bookingId, scope) {
          with (scope) {
            stripe.paymentIntents.create(
              { amount: 100 },
              { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` },
            );
          }
        }
      `,
      "src/lib/jobs/charge.js",
    );
    expect(finding.evidence).toContain("inside JavaScript `with`");
  });

  it("preserves local options, local headers, ordinary block/catch, and classic-for controls", () => {
    expect(
      scan(`
        function charge(stripe: Stripe, tenantId: string, bookingId: string) {
          {
            const options = { idempotencyKey: \`charge:\${tenantId}:\${bookingId}:v1\` };
            stripe.paymentIntents.create({ amount: 100 }, options);
          }
          try {
            throw new Error("retry");
          } catch (error) {
            const headers = { "Idempotency-Key": \`receipt:\${tenantId}:\${bookingId}:v1\` };
            fetch("https://api.resend.com/emails", { method: "POST", headers });
          }
          for (
            const conditionOptions = { idempotencyKey: \`prepare:\${tenantId}:\${bookingId}:v1\` },
              options = { idempotencyKey: \`renew:\${tenantId}:\${bookingId}:v1\` };
            (stripe.paymentIntents.create({ amount: 100 }, conditionOptions), shouldRun);
          ) {
            stripe.subscriptions.create({ customer: bookingId }, options);
            break;
          }
        }
      `),
    ).toEqual([]);
  });

  it("accepts scoped stable keys in Stripe and REST provider option shapes", () => {
    expect(
      scan(`
        export async function charge(stripe: Stripe, tenantId: string, bookingId: string) {
          const key = \`charge:\${tenantId}:\${bookingId}:v1\`;
          await stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: key });
          return fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: new Headers({ "Idempotency-Key": \`receipt:\${tenantId}:\${bookingId}:v1\` }),
          });
        }
      `),
    ).toEqual([]);
  });

  it("is owned by the live registry with exact source-file examined-unit accounting", () => {
    const registered = MECHANICAL_DETECTORS.find((detector) => detector.id === "idempotency");
    expect(registered?.taxonomies).toContain("Idempotency key does not identify a stable scoped operation");
    expect(registered?.applicableFiles.description).toContain("shared inventory");
    expect(registered?.examinedUnits({} as never, [{ path: "src/inngest/job.ts", text: "" }])).toBe(1);
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

// #1352 — item 27, the shape #1230 declined `by-design` on a reach argument. Each negative below is
// a way a real handler already answers the ordering question, so a rule that fired on one would be
// flagging the fix it recommends.
describe("webhook-ordering (item 27)", () => {
  const handler = (body: string, type = "{ id: string; created: number; status: string; ref: string }") =>
    scan(`export async function apply(event: ${type}) {${body}}`, "src/app/api/webhooks/stripe/route.ts");

  it("fires when event-derived state is written with no comparison against the last-applied value", () => {
    const out = handler(`
      await supabase.from("subscriptions").update({ status: event.status }).eq("ref", event.ref);
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Webhook state applied without an ordering guard");
    expect(out[0]!.severity).toBe("Medium");
  });

  it("names the ordering field and its own scope bound in the evidence, not only in a comment", () => {
    const out = handler(`await supabase.from("subscriptions").update({ status: event.status }).eq("ref", event.ref);`);
    expect(out[0]!.evidence).toContain("`created`");
    expect(out[0]!.evidence).toContain("SCOPE OF THIS CHECK: it reads THIS FUNCTION BODY only");
    expect(out[0]!.evidence).toContain("NO webhook-path prefilter");
    expect(out[0]!.evidence).toContain("FIELD PRECISION IS UNMEASURED");
    expect(out[0]!.evidence).toContain("pnpm corpus-drift --install --shard N/3");
    expect(out[0]!.evidence).toContain("13,104 source units across 17 pinned targets");
    expect(out[0]!.evidence).toContain("5eaeb965920aacf2e83c1f78def674691b2f214935990d8ffb85b3d7f73311ff");
  });

  it("is silent when the handler compares the event's ordering field against stored state", () => {
    expect(
      handler(`
        const { data: row } = await supabase.from("subscriptions").select("applied_at").eq("ref", event.ref).single();
        if (row && row.applied_at > event.created) return;
        await supabase.from("subscriptions").update({ status: event.status }).eq("ref", event.ref);
      `),
    ).toEqual([]);
  });

  it("is silent when the guard is the conditional write the fix recommends", () => {
    expect(
      handler(`
        await supabase.from("subscriptions").update({ status: event.status, created: event.created }).eq("ref", event.ref).lt("created", event.created);
      `),
    ).toEqual([]);
  });

  it("is silent when nothing on the event names an ordering field — there is no staleness to compare", () => {
    expect(
      handler(`await supabase.from("subscriptions").update({ status: event.status }).eq("ref", event.ref);`, "{ id: string; status: string; ref: string }"),
    ).toEqual([]);
  });

  // MEASURED over the pinned corpus: 2 of the 6 webhook-path `.update` calls whose argument derived
  // from the handler's first parameter were HMAC digests. A bare `.update(...)` predicate would
  // have graded both.
  it("is silent for `crypto.createHmac(...).update(body)` — the FP the corpus measurement turned up", () => {
    expect(
      handler(`
        const digest = crypto.createHmac("sha256", secret).update(\`\${event.created}.\${event.id}\`).digest("hex");
        return digest;
      `),
    ).toEqual([]);
  });

  it("reads a prisma model write as well as a Supabase chain", () => {
    const out = handler(`await prisma.subscription.updateMany({ where: { ref: event.ref }, data: { status: event.status } });`);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("prisma.subscription");
  });
});
