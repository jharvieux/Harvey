// Physically alter one production boundary at a time and require its real tests to fail.
// The original bytes are restored in a finally block after each child test process.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const appDir = resolve(import.meta.dirname, "..");
const auth = resolve(appDir, "lib/auth.ts");
const route = resolve(appDir, "lib/route.ts");
const controls = [
  {
    name: "password verification bypass", file: auth,
    old: "return typeof expected === \"string\" && expected.length > 0 && constantTimeEqual(password, expected);",
    mutated: "return true;", test: "test/auth.test.ts", failure: "accepts only the configured password",
  },
  {
    name: "missing password falls back to historical default", file: auth,
    old: "return typeof expected === \"string\" && expected.length > 0 && constantTimeEqual(password, expected);",
    mutated: 'return constantTimeEqual(password, process.env.EPIC_BUILDER_PASSWORD ?? "dev-password");',
    test: "test/auth.test.ts", failure: "accepts only the configured password",
  },
  {
    name: "missing signing key falls back to historical default", file: auth,
    old: "return process.env.EPIC_BUILDER_SESSION_SECRET || null;",
    mutated: 'return process.env.EPIC_BUILDER_SESSION_SECRET ?? "dev-insecure-session-secret";',
    test: "test/auth.test.ts", failure: "denies absent signing configuration",
  },
  {
    name: "signature verification bypass", file: auth,
    old: "return constantTimeEqual(mac, sign(VALUE)) ? VALUE : null;",
    mutated: "return VALUE;", test: "test/auth.test.ts", failure: "mints with production code",
  },
  {
    name: "provider mode bypass", file: auth,
    old: 'if (process.env.EPIC_BUILDER_AUTH === "supabase") {',
    mutated: "if (false) {", test: "test/auth.test.ts", failure: "selects the configured cookie",
  },
  {
    name: "provider exception authenticates unverified partition", file: auth,
    old: '} catch {\n    return null;\n  }',
    mutated: '} catch {\n    return "unverified-provider-partition";\n  }',
    test: "test/auth.test.ts", failure: "denies rejected, missing and throwing provider identities",
  },
  {
    name: "route authorization bypass", file: route,
    old: 'if (!userId) return NextResponse.json({ error: "unauthorized" }, { status: 401 });',
    mutated: "if (false) return NextResponse.json({ error: \"unauthorized\" }, { status: 401 });",
    test: "test/routes.test.ts", failure: "denies before invoking core",
  },
  {
    name: "drop successful commit", file: route,
    old: "await acquired.commit();", mutated: "void acquired.commit;",
    test: "test/routes.test.ts", failure: "commits exactly once",
  },
  {
    name: "wrong user partition", file: route,
    old: "acquired = await productionDeps(userId);", mutated: 'acquired = await productionDeps("wrong-user");',
    test: "test/routes.test.ts", failure: "uses the verified partition",
  },
  {
    name: "lose acquired-resource cleanup", file: route,
    old: "await acquired?.release();", mutated: "void acquired?.release;",
    test: "test/routes.test.ts", failure: "releases resources",
  },
];

function run(test) {
  const child = spawnSync("pnpm", ["exec", "vitest", "run", test], {
    cwd: appDir, encoding: "utf8", env: { ...process.env, CI: "true" },
  });
  return { code: child.status ?? 127, output: (child.stdout ?? "") + (child.stderr ?? "") };
}

for (const control of controls) {
  const original = readFileSync(control.file, "utf8");
  assert.equal(original.split(control.old).length, 2, "Mutation anchor is not unique: " + control.name);
  try {
    writeFileSync(control.file, original.replace(control.old, control.mutated));
    const result = run(control.test);
    assert.equal(result.code, 1, control.name + " unexpectedly returned " + result.code + "\n" + result.output);
    assert.ok(result.output.includes(control.failure), control.name + " failed for the wrong reason:\n" + result.output);
    const counts = result.output.match(/Tests\s+([^\n]+)/)?.[1]?.trim() ?? "unreported";
    console.log(JSON.stringify({ mutation: control.name, exitCode: result.code, tests: counts }));
  } finally {
    writeFileSync(control.file, original);
  }
}
const intact = run("test/auth.test.ts");
assert.equal(intact.code, 0, "Restored authentication tests failed:\n" + intact.output);
const restoredRoute = run("test/routes.test.ts");
assert.equal(restoredRoute.code, 0, "Restored route tests failed:\n" + restoredRoute.output);
console.log(JSON.stringify({ restored: true, authExit: intact.code, routeExit: restoredRoute.code }));
