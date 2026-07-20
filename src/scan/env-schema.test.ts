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
});
