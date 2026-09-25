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

function webhookFindings(helper: string, caller: string, dependencies: Record<string, string> = {}) {
  const path = "supabase/functions/stripe-webhook/index.ts";
  return checkUnsignedWebhookHandlers([{ name: "stripe-webhook", path, content: caller }], [
    { path, text: caller },
    { path: "supabase/functions/stripe-webhook/implementation.ts", text: helper },
    { path: "supabase/functions/stripe-webhook/fake.ts", text: `export const crypto = ${fakeCrypto}; export default crypto;` },
    ...Object.entries(dependencies).map(([name, text]) => ({ path: `supabase/functions/stripe-webhook/${name}`, text })),
  ]);
}

function keyFindings(text: string, dependencies: Record<string, string> = {}) {
  const directory = mkdtempSync(join(tmpdir(), "harvey-proof-binding-"));
  try {
    const file = join(directory, "generated.test.ts");
    writeFileSync(file, text);
    for (const [name, source] of Object.entries(dependencies)) writeFileSync(join(directory, name), source);
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

describe("source proof requires inert initialization and a supported execution path (#2130)", () => {
  type Mutation = { name: string; helper?: string; caller?: string; key?: string; safe?: boolean; process?: boolean };
  const mutation = (name: string, prefix: (method: string, result: string) => string): Mutation => ({
    name, helper: prefix("sign", "async () => new Uint8Array([0])"), key: prefix("exportKey", "async () => new Uint8Array([65,65,65])"),
  });
  const mutations: Mutation[] = [
    { name: "genuine positive", key: "", safe: true },
    { name: "harmless literal configuration", helper: 'const label = "webhook";', key: 'const label = "generated";', safe: true },
    mutation("direct property statement", (method, result) => `crypto.subtle.${method} = ${result};`),
    mutation("direct property initializer", (method, result) => `const installed = (crypto.subtle.${method} = ${result});`),
    mutation("Object.assign initializer", (method, result) => `const installed = Object.assign(crypto.subtle, { ${method}: ${result} });`),
    mutation("Object.defineProperty initializer", (method, result) => `const installed = Object.defineProperty(crypto.subtle, "${method}", {value: ${result}});`),
    mutation("Reflect.set initializer", (method, result) => `const installed = Reflect.set(crypto.subtle, "${method}", ${result});`),
    mutation("alias property statement", (method, result) => `const primitive = crypto.subtle; primitive.${method} = ${result};`),
    mutation("alias property initializer", (method, result) => `const primitive = crypto.subtle; const installed = (primitive.${method} = ${result});`),
    mutation("direct-write helper call", (method, result) => `function install() { crypto.subtle.${method} = ${result}; } const installed = install();`),
    mutation("indirect-write helper call", (method, result) => `function install() { return Object.assign(crypto.subtle, {${method}: ${result}}); } const installed = install();`),
    mutation("prototype mutation", (method, result) => `const installed = Object.assign(Object.getPrototypeOf(crypto.subtle), {${method}: ${result}});`),
    mutation("class static initializer", (method, result) => `class Installer { static installed = Object.assign(crypto.subtle, {${method}: ${result}}); }`),
    { name: "TextEncoder prototype", helper: "const installed = Object.assign(TextEncoder.prototype, {encode: () => new Uint8Array([0])});" },
    { name: "Uint8Array replacement", helper: 'const NativeBytes = Uint8Array; const installed = Reflect.set(globalThis, "Uint8Array", function () { return new NativeBytes([0]); });', key: 'const NativeBytes = Uint8Array; const installed = Reflect.set(globalThis, "Uint8Array", function () { return new NativeBytes([65,65,65]); });' },
    { name: "Deno.env property initializer", caller: 'const installed = (Deno.env.get = () => "public-secret");' },
    { name: "Deno.env assign initializer", caller: 'const installed = Object.assign(Deno.env, {get: () => "public-secret"});' },
    { name: "Deno.env alias initializer", caller: 'const environment = Deno.env; const installed = (environment.get = () => "public-secret");' },
    { name: "process.env initializer", caller: 'const installed = (process.env.STRIPE_WEBHOOK_SECRET = "public-secret");', process: true },
  ];

  it.each(mutations)("checks the complete mutation census: $name", (control) => {
    const caller = control.process ? handler.replace('Deno.env.get("STRIPE_WEBHOOK_SECRET")', "process.env.STRIPE_WEBHOOK_SECRET") : handler;
    const findings = webhookFindings(`${control.helper ?? ""}\n${implementation}`, `${control.caller ?? ""}\n${caller}`);
    expect(findings).toHaveLength(control.safe ? 0 : 1);
    if (control.key !== undefined) {
      const keys = keyFindings(`${control.key}\n${generated}`);
      expect(keys).toHaveLength(1);
      expect(keys[0]!.severity).toBe(control.safe ? "Low" : "High");
      if (!control.safe) expect(keys[0]!.fix).not.toContain("No rotation");
    }
  });

  it("checks setup inside the test callback before generating the key", () => {
    const source = 'function install() { Object.assign(crypto.subtle, {exportKey: async () => new Uint8Array([65,65,65])}); }\n'
      + generated.replace("  const keyPair", "  install();\n  const keyPair");
    expect(keyFindings(source)[0]!.severity).toBe("High");
  });

  it.each([
    ["unknown callback runner", generated.replace('it("signs', 'installAndRun("signs')],
    ["another test's setup", 'it("poisons", () => Object.assign(crypto.subtle, {}));\n' + generated],
    ["unknown callback defaults", generated.replace("async () =>", "async (installed = install()) =>")],
  ])("retains review for %s", (_name, source) => {
    expect(keyFindings(source)[0]!.severity).toBe("High");
  });

  it("checks initialization in the imported encoder and its transitive imports", () => {
    const source = 'import {base64UrlFromBytes} from "./encoder.js";\n' + generated.slice(fixtureStart);
    const encoder = 'import "./setup.js";\nexport ' + generated.slice(0, fixtureStart);
    const setup = 'const installed = Object.assign(String, {fromCharCode: () => "A"});';
    expect(keyFindings(source, { "encoder.ts": encoder, "setup.ts": setup })[0]!.severity).toBe("High");
    expect(keyFindings(source, { "encoder.ts": encoder, "setup.ts": 'const label = "inert";' })[0]!.severity).toBe("Low");
  });

  it.each(["caller", "verifier", "re-export"])("checks every runtime dependency of the %s", (place) => {
    const importSetup = 'import "./setup.js";\n';
    const caller = place === "caller" ? importSetup + handler : handler;
    const helper = (place === "verifier" ? importSetup : place === "re-export" ? 'export * from "./setup.js";\n' : "") + implementation;
    expect(webhookFindings(helper, caller, { "setup.ts": 'const installed = Object.assign(crypto.subtle, {sign: async () => new Uint8Array([0])});' })).toHaveLength(1);
    expect(webhookFindings(helper, caller, { "setup.ts": 'const label = "inert";' })).toEqual([]);
  });

  it("rejects an unresolved runtime side-effect import", () => {
    expect(webhookFindings(implementation, 'import "unresolved-setup";\n' + handler)).toHaveLength(1);
  });

  it("retains review for unknown post-verification setup that could affect later requests", () => {
    expect(webhookFindings(implementation.replace('  await params.grantEntitlement', '  const installed = Object.assign(crypto.subtle, {});\n  await params.grantEntitlement'), handler)).toHaveLength(1);
    expect(webhookFindings(implementation, handler.replace('database.entitlements.upsert({ userId })', 'Object.assign(crypto.subtle, {sign: async () => new Uint8Array([0])})'))).toHaveLength(1);
    expect(keyFindings(generated.replace("  await signFixtureJwt(pem);", "  install();\n  await signFixtureJwt(pem);"))[0]!.severity).toBe("High");
    expect(keyFindings('function signFixtureJwt(pem) { Object.assign(crypto.subtle, {}); }\n' + generated)[0]!.severity).toBe("High");
  });
});
