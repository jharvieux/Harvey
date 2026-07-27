// #1230 / D-091 item 12 — a webhook signature decoded with an encoding the provider does not use.
// The SDK-delegating negative is the shipping condition: without it, every handler that hands the
// verification to the provider's own library is a false positive.

import { describe, expect, it } from "vitest";
import { detectWebhookSignatureFindings } from "./webhook-signature.js";

const scan = (text: string, path = "src/app/api/webhooks/route.ts") => detectWebhookSignatureFindings([{ path, text }]);

describe("webhook-signature — fires on a provider/encoding mismatch", () => {
  it("catches a Svix (base64) signature decoded as hex", () => {
    const out = scan(`
      export function verify(req: Request, body: string) {
        const signature = req.headers.get("svix-signature") ?? "";
        const expected = createHmac("sha256", secret).update(body).digest();
        return timingSafeEqual(Buffer.from(signature, "hex"), expected);
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("Webhook signature decoded with the wrong encoding");
    expect(out[0]!.precisionTier).toBe("high");
    expect(out[0]!.title).toContain("base64");
  });

  it("catches the compare side too — a GitHub (hex) signature digested as base64", () => {
    const out = scan(`
      export function verify(req: Request, body: string) {
        const signature = req.headers.get("x-hub-signature-256") ?? "";
        return signature === createHmac("sha256", secret).update(body).digest("base64");
      }
    `);
    expect(out).toHaveLength(1);
  });
});

describe("webhook-signature — silent unless both halves are present and disagree", () => {
  it("is silent when the encoding matches the provider", () => {
    expect(
      scan(`
        export function verify(req: Request, body: string) {
          const signature = req.headers.get("x-shopify-hmac-sha256") ?? "";
          return timingSafeEqual(Buffer.from(signature, "base64"), createHmac("sha256", secret).update(body).digest());
        }
      `),
    ).toEqual([]);
  });

  it("is silent when the provider SDK owns the decode — there is no encoding literal to judge", () => {
    expect(
      scan(`
        export function verify(req: Request, body: string) {
          const signature = req.headers.get("stripe-signature") ?? "";
          return stripe.webhooks.constructEvent(body, signature, secret);
        }
      `),
    ).toEqual([]);
  });

  it("is silent on a header the provider table does not know — guessing is worse than the gap", () => {
    expect(
      scan(`
        export function verify(req: Request, body: string) {
          const signature = req.headers.get("x-acme-signature") ?? "";
          return timingSafeEqual(Buffer.from(signature, "hex"), createHmac("sha256", secret).update(body).digest());
        }
      `),
    ).toEqual([]);
  });

  it("scopes to the function — a correct handler next door does not clear a wrong one", () => {
    const out = scan(`
      export function verifyGithub(req: Request, body: string) {
        const signature = req.headers.get("x-hub-signature-256") ?? "";
        return timingSafeEqual(Buffer.from(signature, "hex"), createHmac("sha256", secret).update(body).digest());
      }
      export function verifySvix(req: Request, body: string) {
        const signature = req.headers.get("svix-signature") ?? "";
        return timingSafeEqual(Buffer.from(signature, "hex"), createHmac("sha256", secret).update(body).digest());
      }
    `);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("svix-signature");
  });
});
