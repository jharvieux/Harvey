import { describe, expect, it } from "vitest";
import { detectSecretRotationFindings } from "./secret-rotation.js";

const TAX = "Static secret verified with no rotation-pair acceptance window";
const file = (text: string, path = "app/api/webhook/route.ts") => [{ path, text }];
const flagged = (files: { path: string; text: string }[]) => detectSecretRotationFindings(files).some((f) => f.taxonomy === TAX);

describe("detectSecretRotationFindings (#680 — single-secret verify with no rotation window)", () => {
  it("flags a single-secret timingSafeEqual verify with no sibling variant", () => {
    const text = `
      import { timingSafeEqual } from "node:crypto";
      export async function POST(req) {
        const sig = req.headers.get("x-signature");
        if (!timingSafeEqual(Buffer.from(sig), Buffer.from(process.env.WEBHOOK_SECRET))) {
          return new Response("bad sig", { status: 401 });
        }
      }
    `;
    const findings = detectSecretRotationFindings(file(text)).filter((f) => f.taxonomy === TAX);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "Medium", precisionTier: "review", category: "Secrets management" });
    expect(findings[0]?.evidence).toContain("WEBHOOK_SECRET");
  });

  it("flags a single-secret === verify against a secret-named env var", () => {
    const text = `
      export async function POST(req) {
        const token = req.headers.get("authorization");
        if (token !== process.env.API_SIGNING_TOKEN) return new Response("no", { status: 401 });
      }
    `;
    expect(flagged(file(text))).toBe(true);
  });

  it("stays clean when a sibling rotation variant is read anywhere in the codebase", () => {
    const verify = {
      path: "app/api/webhook/route.ts",
      text: `
        import { timingSafeEqual } from "node:crypto";
        export async function POST(req) {
          const sig = req.headers.get("x-signature");
          if (timingSafeEqual(Buffer.from(sig), Buffer.from(process.env.WEBHOOK_SECRET))) return;
        }
      `,
    };
    const config = { path: "lib/rotate.ts", text: `export const prev = process.env.WEBHOOK_SECRET_PREVIOUS;` };
    expect(flagged([verify, config])).toBe(false);
  });

  it("stays clean when the comparison already accepts more than one secret (array .some)", () => {
    const text = `
      import { timingSafeEqual } from "node:crypto";
      export async function POST(req) {
        const sig = Buffer.from(req.headers.get("x-signature"));
        const ok = [process.env.WEBHOOK_SECRET, process.env.WEBHOOK_SECRET_OLD].some(
          (s) => timingSafeEqual(sig, Buffer.from(s)),
        );
        if (!ok) return new Response("no", { status: 401 });
      }
    `;
    expect(flagged(file(text))).toBe(false);
  });

  it("is inert on a plain app with no secret-verify site (config compare is not a verify)", () => {
    const text = `
      export function GET() {
        if (process.env.NODE_ENV === "production") return new Response("prod");
        return new Response("dev");
      }
    `;
    expect(detectSecretRotationFindings(file(text))).toHaveLength(0);
  });

  it("emits at review tier, never free-count", () => {
    const text = `
      import { timingSafeEqual } from "node:crypto";
      export async function POST(req) {
        const sig = Buffer.from(req.headers.get("x-sig"));
        if (!timingSafeEqual(sig, Buffer.from(process.env.STRIPE_WEBHOOK_SECRET))) return;
      }
    `;
    const findings = detectSecretRotationFindings(file(text)).filter((f) => f.taxonomy === TAX);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.precisionTier).toBe("review");
  });
});
