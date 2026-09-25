import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseGitleaksFindings } from "./secrets.js";
import { checkUnsignedWebhookHandlers } from "./supabase-config.js";

const fixture = (name: string) => readFileSync(new URL(`./__fixtures__/source-precision/${name}`, import.meta.url), "utf8");
const handler = fixture("webhook-valid/handler.ts.txt").replace("./shared.js", "./implementation.ts");
const implementation = fixture("webhook-valid/implementation.ts.txt");
const generated = fixture("generated-private-key.test.ts.txt");
const fakeCrypto = "{ subtle: { importKey: async () => ({}), sign: async () => new Uint8Array([0]), generateKey: async () => ({privateKey:{}}), exportKey: async () => new Uint8Array([65,65,65]) } }";
const fixtureStart = generated.indexOf("it(");

// These are distinct emitted runtime bindings, including the verifier's independently
// reproduced census. The scanner sees the real reference site, not just the declaration.
const cases: readonly [string, string, string, string][] = [
  ["class declaration", `class crypto { static subtle = ${fakeCrypto}.subtle; }\n${implementation}`, handler, `class crypto { static subtle = ${fakeCrypto}.subtle; }\n${generated}`],
  ["namespace", `namespace crypto { export const subtle = ${fakeCrypto}.subtle; }\n${implementation}`, handler, `namespace crypto { export const subtle = ${fakeCrypto}.subtle; }\n${generated}`],
  ["merged enum and namespace", `enum crypto {}\nnamespace crypto { export const subtle = ${fakeCrypto}.subtle; }\n${implementation}`, handler, `enum crypto {}\nnamespace crypto { export const subtle = ${fakeCrypto}.subtle; }\n${generated}`],
  ["variable function expression", `const crypto = function () {};\n${implementation}`, handler, `const Uint8Array = function () { return [65,65,65]; };\n${generated}`],
  ["variable class expression", `const crypto = class { static subtle = ${fakeCrypto}.subtle; };\n${implementation}`, handler, `const Uint8Array = class { constructor() { return [65,65,65]; } };\n${generated}`],
  ["function declaration", `function crypto() {}\n${implementation}`, handler, `function Uint8Array() { return new globalThis.Uint8Array([65,65,65]); }\n${generated}`],
  ["destructured variable", `const {crypto} = {crypto: ${fakeCrypto}};\n${implementation}`, handler, `const {crypto} = {crypto: ${fakeCrypto}};\n${generated}`],
  ...["import {crypto}", "import crypto", "import * as crypto"].map((prefix): [string, string, string, string] => [prefix, `${prefix} from "./fake.ts";\n${implementation}`, handler, `${prefix} from "./fake.ts";\n${generated}`]),
  ["import equals", `namespace platform { export const fake = ${fakeCrypto}; }\nimport crypto = platform.fake;\n${implementation}`, handler, `namespace platform { export const fake = ${fakeCrypto}; }\nimport crypto = platform.fake;\n${generated}`],
  ["parameter", implementation.replace("processWebhook(params:", "processWebhook(crypto, params:"), handler, generated.replace("async () => {", "async (crypto) => {")],
  ["destructured parameter", implementation.replace("processWebhook(params:", "processWebhook({crypto}, params:"), handler, generated.replace("async () => {", "async ({crypto}) => {")],
  ["hoisted nested function after return", implementation, handler.replace("\n}", '\n  function processWebhook() { return database.entitlements.upsert({userId: "forged"}); }\n}'), generated.replace("  await signFixtureJwt(pem);", '  function base64UrlFromBytes() { return "STATIC_COMMITTED_KEY"; }\n  await signFixtureJwt(pem);')],
  ["catch destructuring", implementation, handler.replace("  const rawBody =", "  try { throw {}; } catch ({Deno}) {\n  const rawBody =").replace("\n}", "\n  }\n}"), generated.slice(0, fixtureStart) + `try { throw {crypto:${fakeCrypto}}; } catch ({crypto}) {\n` + generated.slice(fixtureStart) + "\n}"],
  ["named function expression", implementation, handler.replace("  const rawBody =", "  const processWebhook = function processWebhook() { return true; };\n  const rawBody ="), generated.slice(0, fixtureStart) + '(function base64UrlFromBytes(bytes) { if (bytes) return "STATIC_COMMITTED_KEY";\n' + generated.slice(fixtureStart) + "\n})();"],
  ["named class expression", implementation, handler.replace("  const rawBody =", "  const processWebhook = class processWebhook {};\n  const rawBody ="), generated.slice(0, fixtureStart) + "const holder = class Uint8Array { constructor() { return new globalThis.Uint8Array([65,65,65]); } static run() {\n" + generated.slice(fixtureStart) + "\n} }; holder.run();"],
];

function webhookFindings(helper: string, caller: string) {
  const path = "supabase/functions/stripe-webhook/index.ts";
  return checkUnsignedWebhookHandlers([{ name: "stripe-webhook", path, content: caller }], [
    { path, text: caller },
    { path: "supabase/functions/stripe-webhook/implementation.ts", text: helper },
    { path: "supabase/functions/stripe-webhook/fake.ts", text: `export const crypto = ${fakeCrypto}; export default crypto;` },
  ]);
}

function keyFindings(text: string) {
  const directory = mkdtempSync(join(tmpdir(), "harvey-proof-binding-"));
  try {
    const file = join(directory, "generated.test.ts");
    writeFileSync(file, text);
    return parseGitleaksFindings([{ RuleID: "private-key", File: file, Match: text.split("`")[1], StartLine: text.slice(0, text.indexOf("-----BEGIN")).split("\n").length }], "source");
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

describe("source proof resolves every runtime binding through the compiler (#2130)", () => {
  it.each(cases)("keeps %s as explicit review in both production consumers", (_name, helper, caller, key) => {
    const webhook = webhookFindings(helper, caller);
    expect(webhook).toHaveLength(1);
    expect(webhook[0]!.precisionTier).toBe("review");
    const credential = keyFindings(key);
    expect(credential).toHaveLength(1);
    expect(credential[0]!.severity).toBe("High");
    expect(credential[0]!.evidence).toContain("provenance was not proved");
    expect(credential[0]!.fix).not.toContain("No rotation");
  });

  it("preserves the evidenced HMAC and generated-key positives", () => {
    expect(webhookFindings(implementation, handler)).toEqual([]);
    expect(keyFindings(generated)[0]!.severity).toBe("Low");
  });

  it("does not confuse an unrelated sibling scope with the actual reference", () => {
    const sibling = "function unrelated() { class crypto {}; function Uint8Array() {}; function base64UrlFromBytes() {}; return crypto; }\n";
    expect(webhookFindings(sibling + implementation, handler)).toEqual([]);
    expect(keyFindings(sibling + generated)[0]!.severity).toBe("Low");
  });

  it.each(["class Deno {}", "namespace Deno { export const env = {get: () => 'attacker-known'}; }", "enum Deno {}", "import Deno = platform.fake;"])("rejects caller platform replacement: %s", (replacement) => {
    expect(webhookFindings(implementation, replacement + "\n" + handler)).toHaveLength(1);
  });
});
