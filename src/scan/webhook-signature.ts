// #1230 / D-091 item 12 — WEBHOOK-SIG-ENCODING. A webhook signature decoded with an encoding the
// provider does not use (hex vs base64 vs base64url). Every valid delivery then fails
// verification, so the handler — and every enforcement behind it — is silently inoperative:
// nothing throws, nothing logs, and unit tests pass because the mock signature is produced by the
// same wrong decode. ATC's instance was `Buffer.from(sig, "hex")` against a Svix (base64) header.
//
// #1230 recorded this as needing "a per-provider expected-encoding table Harvey doesn't have".
// The table is five rows and the header name carries the provider, so that is what this ships:
// the SIGNATURE HEADER NAME is the provider oracle, not the file path or a package import. Each
// row below is the provider's own documented signature format:
//   svix-signature / webhook-signature  Svix (Resend, Clerk, …)  `v1,<base64>`
//   x-hub-signature-256 / x-hub-signature  GitHub                `sha256=<hex>`
//   x-shopify-hmac-sha256               Shopify                  base64
//   x-slack-signature                   Slack                    `v0=<hex>`
//   stripe-signature                    Stripe                   `t=…,v1=<hex>`
//
// SCOPE, and why it does not over-fire: a finding needs BOTH a provider header read AND at least
// one encoding literal (`Buffer.from(x, "<enc>")` / `.digest("<enc>")`) in the SAME function, and
// fires only when no encoding literal there matches the provider's. A handler that delegates to
// the provider SDK (`stripe.webhooks.constructEvent`) has no encoding literal, so it is silent —
// correctly, since the SDK owns the decode. A header this table does not know is silent too: the
// failure mode of guessing an encoding is worse than the gap, and the table is the disclosed
// boundary. High tier: when it fires, the mismatch is a fact about two string literals, not a
// judgement about the code's intent.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

// header name (lowercase) → { provider, the encoding the provider actually sends }
const PROVIDER_ENCODING: Record<string, { provider: string; encoding: string }> = {
  "svix-signature": { provider: "Svix (Resend/Clerk)", encoding: "base64" },
  "webhook-signature": { provider: "Svix (Resend/Clerk)", encoding: "base64" },
  "x-hub-signature-256": { provider: "GitHub", encoding: "hex" },
  "x-hub-signature": { provider: "GitHub", encoding: "hex" },
  "x-shopify-hmac-sha256": { provider: "Shopify", encoding: "base64" },
  "x-slack-signature": { provider: "Slack", encoding: "hex" },
  "stripe-signature": { provider: "Stripe", encoding: "hex" },
};

const ENCODING_LITERAL = /^(hex|base64|base64url)$/;

function isFunctionLike(n: ts.Node): boolean {
  return ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n);
}

interface Observed {
  header?: { name: string; node: ts.Node };
  encodings: { value: string; node: ts.Node }[];
}

function observe(fn: ts.Node): Observed {
  const out: Observed = { encodings: [] };
  const visit = (n: ts.Node) => {
    if (ts.isStringLiteralLike(n) && !out.header) {
      const key = n.text.toLowerCase();
      if (PROVIDER_ENCODING[key]) out.header = { name: key, node: n };
    }
    if (ts.isCallExpression(n)) {
      const callee = n.expression;
      // Buffer.from(<sig>, "<enc>") — the decode side.
      const isBufferFrom =
        ts.isPropertyAccessExpression(callee) && callee.name.text === "from" && callee.expression.getText() === "Buffer";
      // .digest("<enc>") — the compare side.
      const isDigest = ts.isPropertyAccessExpression(callee) && callee.name.text === "digest";
      const arg = isBufferFrom ? n.arguments[1] : isDigest ? n.arguments[0] : undefined;
      if (arg && ts.isStringLiteralLike(arg) && ENCODING_LITERAL.test(arg.text)) {
        out.encodings.push({ value: arg.text, node: arg });
      }
    }
    if (!isFunctionLike(n) || n === fn) ts.forEachChild(n, visit);
  };
  ts.forEachChild(fn, visit);
  return out;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (isFunctionLike(n)) {
      const { header, encodings } = observe(n);
      if (header && encodings.length > 0) {
        const expected = PROVIDER_ENCODING[header.name]!;
        if (!encodings.some((e) => e.value === expected.encoding)) {
          const used = [...new Set(encodings.map((e) => e.value))].join("/");
          findings.push(
            mechanicalFinding({
              id: `WEBHOOK-sig-encoding-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${encodings[0]!.node.getStart(sf)}`,
              title: `${path} — webhook signature decoded as ${used}, but ${expected.provider} sends ${expected.encoding}`,
              severity: "High",
              category: "Broken access control",
              taxonomy: "Webhook signature decoded with the wrong encoding",
              location: loc(path, sf, encodings[0]!.node),
              evidence:
                `Heuristic "webhook-signature-encoding" matched the \`${header.name}\` header (${expected.provider}, documented encoding \`${expected.encoding}\`) verified with \`${used}\` and no \`${expected.encoding}\` decode anywhere in the same function.`,
              impact:
                "Every genuine delivery fails signature verification, so the handler never runs and everything it enforces is inoperative — silently, since a mismatch produces no error and unit tests built on the same wrong decode still pass.",
              fix: `Decode the \`${header.name}\` signature as \`${expected.encoding}\`, and add a verification test built from a real recorded delivery from ${expected.provider} rather than a self-generated mock.`,
              precisionTier: "high",
            }),
          );
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectWebhookSignatureFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
