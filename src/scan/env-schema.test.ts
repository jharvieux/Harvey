import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { SourceInput } from "../detectors/common.js";
import { detectEnvSchemaFindings } from "./env-schema.js";

const UNDECLARED = "Env var read but not declared in env schema";
const UNUSED = "Env var declared in env schema but never read";

const fixture = (name: string): string => readFileSync(new URL(`./fixtures/env-schema/${name}`, import.meta.url), "utf8");

// The fixture "project": a @t3-oss env schema module and a product file reading process.env.
// Fixtures live as .txt so tsc/knip/eslint don't compile them; the test assigns real .ts paths.
const schema: SourceInput = { path: "src/lib/env.ts", text: fixture("env.ts.txt") };
const reads: SourceInput = { path: "src/app/config.ts", text: fixture("reads.ts.txt") };

const run = (files: SourceInput[]) => detectEnvSchemaFindings(files);
const undeclaredKeys = (files: SourceInput[]) => run(files).filter((f) => f.taxonomy === UNDECLARED).map((f) => f.id);
const unusedKeys = (files: SourceInput[]) => run(files).filter((f) => f.taxonomy === UNUSED).map((f) => f.id);

describe("detectEnvSchemaFindings", () => {
  it("flags a read of a key that is not declared in the schema", () => {
    expect(undeclaredKeys([schema, reads])).toContain("ENV-undeclared-read-SENDGRID_API_KEY");
  });

  it("recognizes bracket-access reads (process.env[\"X\"]) the same as dotted ones", () => {
    // SENDGRID_API_KEY is read via process.env["SENDGRID_API_KEY"] in the fixture.
    const finding = run([schema, reads]).find((f) => f.id === "ENV-undeclared-read-SENDGRID_API_KEY");
    expect(finding?.location).toBe("src/app/config.ts:6");
  });

  it("flags an undeclared client-exposed (NEXT_PUBLIC_*) read and says so in the impact", () => {
    const finding = run([schema, reads]).find((f) => f.id === "ENV-undeclared-read-NEXT_PUBLIC_ANALYTICS_ID");
    expect(finding).toBeDefined();
    expect(finding?.impact).toContain("client-exposed");
  });

  it("does NOT flag keys that are both declared and read", () => {
    const ids = undeclaredKeys([schema, reads]);
    expect(ids).not.toContain("ENV-undeclared-read-DATABASE_URL");
    expect(ids).not.toContain("ENV-undeclared-read-STRIPE_SECRET_KEY");
    expect(ids).not.toContain("ENV-undeclared-read-NEXT_PUBLIC_APP_URL");
  });

  it("does NOT flag runtime/framework builtins like NODE_ENV", () => {
    expect(undeclaredKeys([schema, reads])).not.toContain("ENV-undeclared-read-NODE_ENV");
  });

  it("flags a declared-but-never-read key at Info level", () => {
    const finding = run([schema, reads]).find((f) => f.id === "ENV-unused-declaration-UNUSED_LEGACY_TOKEN");
    expect(finding?.severity).toBe("Info");
    expect(finding?.taxonomy).toBe(UNUSED);
  });

  it("does NOT count the schema module's own process.env wiring as an app read", () => {
    // env.ts references process.env.UNUSED_LEGACY_TOKEN in runtimeEnv; that must not clear the
    // unused-declaration finding, and must not itself be reported as an undeclared read.
    expect(unusedKeys([schema, reads])).toContain("ENV-unused-declaration-UNUSED_LEGACY_TOKEN");
    expect(undeclaredKeys([schema, reads])).not.toContain("ENV-undeclared-read-UNUSED_LEGACY_TOKEN");
  });

  it("emits nothing when there is no env schema module to diff against", () => {
    expect(run([reads])).toHaveLength(0);
  });

  it("does not treat reads in test/fixture files as product reads", () => {
    const testFile: SourceInput = { path: "src/app/config.test.ts", text: `const x = process.env.ONLY_IN_TESTS;` };
    expect(undeclaredKeys([schema, reads, testFile])).not.toContain("ENV-undeclared-read-ONLY_IN_TESTS");
  });

  it("emits at review tier (heuristic diff), never free-count", () => {
    for (const f of run([schema, reads])) expect(f.precisionTier).toBe("review");
  });

  it("recognizes the zod `schema.parse(process.env)` shape and diffs its declared keys", () => {
    const zodSchema: SourceInput = {
      path: "src/config/env.ts",
      text: `import { z } from "zod";
        const schema = z.object({ DATABASE_URL: z.string(), API_KEY: z.string() });
        export const env = schema.parse(process.env);`,
    };
    const app: SourceInput = {
      path: "src/server.ts",
      text: `const a = process.env.DATABASE_URL; const b = process.env.WEBHOOK_SECRET;`,
    };
    const ids = undeclaredKeys([zodSchema, app]);
    expect(ids).toContain("ENV-undeclared-read-WEBHOOK_SECRET"); // read, not in the z.object
    expect(ids).not.toContain("ENV-undeclared-read-DATABASE_URL"); // declared in the z.object
  });

  it("does not treat a helper that validates one value with zod as the env schema", () => {
    // `.object({ url }).parse({ url: process.env.X })` validates ONE value, not process.env — it
    // is not the app's env schema, so no diff runs and nothing is flagged. (Guards the
    // calibration redis.js false positive.)
    const helper: SourceInput = {
      path: "lib/redis.ts",
      text: `import { z } from "zod";
        const C = z.object({ url: z.string().url() });
        export const redisUrl = () => C.parse({ url: process.env.REDIS_URL }).url;`,
    };
    const app: SourceInput = { path: "src/server.ts", text: `const x = process.env.SOME_OTHER_VAR;` };
    expect(run([helper, app])).toHaveLength(0);
  });

  // #902 — framework-aware env conventions.
  describe("framework-aware conventions (#902)", () => {
    const viteSchema: SourceInput = {
      path: "src/env.ts",
      text: `import { z } from "zod";
        const schema = z.object({ VITE_API_URL: z.string() });
        export const env = schema.parse(import.meta.env);`,
    };
    const viteReads: SourceInput = {
      path: "src/app.ts",
      text: `const a = import.meta.env.VITE_API_URL; const b = import.meta.env.VITE_ANALYTICS_ID;`,
    };

    it("collects import.meta.env reads and recognizes a .parse(import.meta.env) schema on Vite", () => {
      const ids = detectEnvSchemaFindings([viteSchema, viteReads], "vite")
        .filter((f) => f.taxonomy === UNDECLARED)
        .map((f) => f.id);
      expect(ids).toContain("ENV-undeclared-read-VITE_ANALYTICS_ID"); // read, not declared
      expect(ids).not.toContain("ENV-undeclared-read-VITE_API_URL"); // declared in the schema
    });

    it("marks a VITE_-prefixed undeclared read client-exposed on Vite", () => {
      const finding = detectEnvSchemaFindings([viteSchema, viteReads], "vite").find(
        (f) => f.id === "ENV-undeclared-read-VITE_ANALYTICS_ID",
      );
      expect(finding?.impact).toContain("client-exposed");
      expect(finding?.impact).toContain("VITE_");
    });

    it("does NOT collect import.meta.env reads on a Next target (server compiler, process.env only)", () => {
      // A stray import.meta.env read on a Next app is not this framework's convention — not collected,
      // so it can't false-fire as an undeclared read.
      const found = detectEnvSchemaFindings([schema, { path: "src/x.ts", text: `const a = import.meta.env.VITE_X;` }], "next");
      expect(found.map((f) => f.id)).not.toContain("ENV-undeclared-read-VITE_X");
    });

    it("does NOT mark a VITE_ read client-exposed on a Next target (wrong prefix for the framework)", () => {
      // Same fixture, but the client-exposed prefix set is framework-specific: on Next, VITE_ is not it.
      const nextViteReads: SourceInput = { path: "src/app.ts", text: `const a = process.env.VITE_LEGACY;` };
      const finding = detectEnvSchemaFindings([schema, nextViteReads], "next").find(
        (f) => f.id === "ENV-undeclared-read-VITE_LEGACY",
      );
      expect(finding?.impact).not.toContain("client-exposed");
    });

    it("discloses SvelteKit $env usage as a not-assessed convention (even with no process.env schema)", () => {
      const svelte: SourceInput = { path: "src/routes/+page.server.ts", text: `import { SECRET_KEY } from "$env/static/private";` };
      const findings = detectEnvSchemaFindings([svelte], "sveltekit");
      const disclosure = findings.find((f) => f.id === "ENV-SCHEMA-CONVENTION-00");
      expect(disclosure).toBeDefined();
      expect(disclosure).toMatchObject({ severity: "Info", confidence: "N/A" });
      expect(disclosure?.impact).toContain("PARTIAL");
    });

    it("discloses Nuxt runtimeConfig usage as a not-assessed convention", () => {
      const nuxt: SourceInput = { path: "nuxt.config.ts", text: `export default defineNuxtConfig({ runtimeConfig: { apiSecret: "" } });` };
      expect(detectEnvSchemaFindings([nuxt], "nuxt").some((f) => f.id === "ENV-SCHEMA-CONVENTION-00")).toBe(true);
    });

    it("does not disclose on a SvelteKit target that uses no $env modules (no noise)", () => {
      const plain: SourceInput = { path: "src/routes/+page.ts", text: `export const load = () => ({ ok: true });` };
      expect(detectEnvSchemaFindings([plain], "sveltekit").some((f) => f.id === "ENV-SCHEMA-CONVENTION-00")).toBe(false);
    });
  });
});
