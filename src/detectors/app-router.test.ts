import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectAppRouterFindings, type SourceInput } from "./app-router.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/", import.meta.url));

// Fixtures are stored as `<name>.txt` so tsc/knip/eslint don't try to compile
// them as real project sources (they intentionally reference packages this
// repo doesn't depend on, e.g. zod, server-only, @supabase/supabase-js).
// This loader strips the `.txt` suffix to recover the logical source path
// (e.g. "app/dashboard/page.tsx") the detector expects.
function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (entry.endsWith(".txt")) {
        const path = relative(root, full).replace(/\.txt$/, "").split(sep).join("/");
        files.push({ path, text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

function taxonomies(findings: ReturnType<typeof detectAppRouterFindings>): string[] {
  return findings.map((f) => f.taxonomy);
}

describe("server → client data leak", () => {
  it("flags a full DB row passed whole as a prop to a 'use client' component", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-client-leak/positive"));
    const leaks = findings.filter((f) => f.taxonomy === "M9 — Server→client data leak");

    expect(leaks).toHaveLength(1);
    expect(leaks[0]).toMatchObject({ severity: "High", category: "Security" });
    expect(leaks[0]?.location).toBe("app/dashboard/page.tsx:7");
    expect(leaks[0]?.evidence).toContain("user={user}");
  });

  it("does not flag a projected/narrowed prop passed to the same client component", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-client-leak/negative"));
    expect(taxonomies(findings)).not.toContain("M9 — Server→client data leak");
  });

  // #380: the client component is imported via the create-next-app `@/*` path alias, not a
  // relative specifier. Before the tsconfig `paths` resolution, the leak was invisible.
  it("follows a tsconfig `@/*` path alias to identify the imported Client Component", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-client-leak/positive-aliased"));
    const leaks = findings.filter((f) => f.taxonomy === "M9 — Server→client data leak");

    expect(leaks).toHaveLength(1);
    expect(leaks[0]?.location).toBe("app/dashboard/page.tsx:7");
    expect(leaks[0]?.evidence).toContain("user={user}");
  });

  it("stays silent when an aliased import resolves to a Server (non-'use client') Component", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-client-leak/negative-aliased"));
    expect(taxonomies(findings)).not.toContain("M9 — Server→client data leak");
  });
});

describe("missing server-only guard", () => {
  it("flags a module reading a service-role/secret env var with no 'server-only' import, when a real client-import path reaches it", () => {
    // #231: the positive fixture now includes a 'use client' component that actually imports
    // the module — the missing guard only matters once there's a real bundling risk.
    const findings = detectAppRouterFindings(loadFixtureDir("missing-server-only/positive"));
    const hits = findings.filter((f) => f.taxonomy === "M9 — Missing server-only guard");

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security", location: "lib/admin-client.ts:1" });
  });

  it("does not flag a module once it imports 'server-only', a route handler touching the same secret, a module with no secret access, or a secret access no client code imports", () => {
    // negative/ covers four distinct non-findings: the guard present, the
    // route-handler exemption (server-exclusive by Next.js routing convention),
    // a module that never touches a secret at all, and (#231) a secret-touching
    // module nothing on the client side ever imports.
    const findings = detectAppRouterFindings(loadFixtureDir("missing-server-only/negative"));
    expect(findings.filter((f) => f.taxonomy === "M9 — Missing server-only guard")).toHaveLength(0);
  });

  // #380: the client component reaches the secret module through a `@/lib/...` aliased edge, so
  // the real-client-import-path graph must follow tsconfig `paths`, not just relative imports.
  it("follows a tsconfig `@/*` aliased import edge in the real-client-import-path graph", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("missing-server-only/positive-aliased"));
    const hits = findings.filter((f) => f.taxonomy === "M9 — Missing server-only guard");

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security", location: "lib/admin-client.ts:1" });
  });

  it("stays silent when the aliased-imported secret module already imports 'server-only'", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("missing-server-only/negative-aliased"));
    expect(findings.filter((f) => f.taxonomy === "M9 — Missing server-only guard")).toHaveLength(0);
  });

  it("does not flag on a Pages Router project — App-Router-only checks don't apply there (#231)", () => {
    // Pathological but decisive: a stray 'use client' marker inside a pages/-only tree (no
    // app/ dir anywhere) would otherwise satisfy the real-client-import-path gate above — the
    // Pages Router short-circuit is what actually suppresses it here.
    const findings = detectAppRouterFindings(loadFixtureDir("missing-server-only/negative-pages-router-only"));
    expect(findings.filter((f) => f.taxonomy === "M9 — Missing server-only guard")).toHaveLength(0);
  });
});

describe("Server Action missing auth", () => {
  it("flags a 'use server' action that mutates data with no auth check, routed to the M1 authorization class (#221) rather than M9 rendering", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-auth/positive"));
    const hits = findings.filter((f) => f.taxonomy === "M1 — Server Action missing authorization check");

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security" });
    expect(hits[0]?.title).toContain("deleteAccount");
    expect(taxonomies(findings)).not.toContain("M9 — Server Action missing auth");
  });

  it("does not flag the same action once it checks the caller's session before mutating", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-auth/negative"));
    expect(taxonomies(findings)).not.toContain("M1 — Server Action missing authorization check");
  });
});

const CLIENT_OWNER_ID = "M1 — Client-supplied owner id trusted by authenticated action";

// #221. The gap this closes: the missing-auth check above is satisfied by the mere PRESENCE
// of an auth call, so an action that authenticates and then scopes its mutation by a
// client-supplied owner id produced no finding at all. Every negative here is a near-miss —
// it carries the auth call, the mutation, and an ownership `.eq()` — so a rule that simply
// matched "server action reading its arguments" would fail them.
describe("client-supplied owner id trusted by an authenticated action (#221)", () => {
  it("flags an authenticated, schema-validated action whose mutation is scoped by a client-supplied user_id", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/positive"));
    const hits = findings.filter((f) => f.taxonomy === CLIENT_OWNER_ID);

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security", confidence: "Likely" });
    expect(hits[0]?.title).toContain("updateMemberRole");
    expect(hits[0]?.location).toBe("app/actions.ts:19");
    expect(hits[0]?.evidence).toContain("currentUser");
    // The action DOES authenticate and DOES validate — neither of the older checks fires,
    // which is exactly why this class needed its own detector rather than a widened rule.
    expect(taxonomies(findings)).not.toContain("M1 — Server Action missing authorization check");
    expect(taxonomies(findings)).not.toContain("M9 — Server Action missing input validation");
  });

  it("flags a second instance of the class exercising the delete verb and the account_id column", () => {
    // The negative-ownership-compared shape with its session-vs-client guard removed: a real
    // .delete() scoped by a client-supplied account_id. Guards a partial regression of the
    // MUTATION_PATTERN (delete) / OWNERSHIP_COLUMN (account_id) surfaces the user_id/update
    // positive never exercises.
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/positive-delete"));
    const hits = findings.filter((f) => f.taxonomy === CLIENT_OWNER_ID);

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security", confidence: "Likely" });
    expect(hits[0]?.title).toContain("deleteAccount");
    expect(hits[0]?.evidence).toContain("account_id");
  });

  it("does not flag the same shape when the owner id is read off the session binding", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/negative-session-derived"));
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
  });

  it("does not flag a client-supplied id that is explicitly compared against the session's before mutating", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/negative-ownership-compared"));
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
  });

  it("does not flag a read-only action scoped by a client-supplied owner id (RLS's job, not a mutation gap)", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nimport { getCurrentUser } from "../lib/auth";\nexport async function listInvoices(input: { tenantId: string }) {\n  const user = await getCurrentUser();\n  return admin.from("invoices").select("*").eq("tenant_id", input.tenantId);\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
  });

  it("does not flag a mutation scoped by a client-supplied non-ownership column", () => {
    // `.eq("status", …)` from the client is an ordinary filter, not an authorization decision —
    // pins the rule to ownership columns rather than "any .eq() fed an argument".
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nimport { getCurrentUser } from "../lib/auth";\nexport async function archive(input: { status: string }) {\n  const user = await getCurrentUser();\n  await admin.from("tasks").update({ archived: true }).eq("status", input.status).eq("user_id", user.id);\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
  });

  it("does not flag an owner id that roots in neither the parameters nor the session — client origin is not established", () => {
    // `.eq("user_id", resolveTenant().id)` roots in a call, not an argument. Pins the rule to a
    // PROVEN client root: without this the safe default (silence) could invert into "unknown =
    // client-supplied", which would flag every helper-derived owner id in a real codebase.
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nimport { getCurrentUser } from "../lib/auth";\nexport async function update(input: { bio: string }) {\n  const user = await getCurrentUser();\n  await admin.from("profiles").update({ bio: input.bio }).eq("user_id", resolveTenant().id);\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
  });

  it("does not flag when auth is called but nothing is bound from it — authorization may live in code this pass cannot see", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nimport { requireUser } from "../lib/auth";\nexport async function update(input: { userId: string; bio: string }) {\n  await requireUser();\n  await admin.from("profiles").update({ bio: input.bio }).eq("user_id", input.userId);\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
  });
});

describe("Server Action missing input validation", () => {
  it("flags a 'use server' action that mutates from formData with no schema parse", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-validation/positive"));
    const hits = findings.filter((f) => f.taxonomy === "M9 — Server Action missing input validation");

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security" });
    expect(hits[0]?.title).toContain("updateProfile");
  });

  it("does not flag the same action once its input is parsed through a Zod schema", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-validation/negative"));
    expect(taxonomies(findings)).not.toContain("M9 — Server Action missing input validation");
  });

  it("does not flag read-only 'use server' actions (no mutation call)", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nexport async function getProfile(id: string) {\n  return supabase.from("profiles").select("*").eq("id", id).single();\n}\n`,
      },
    ]);
    expect(findings).toEqual([]);
  });
});

describe("unsafe/missing cache config (MED, best-effort)", () => {
  it("flags a page querying the DB with no cache signal anywhere in the file", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-config/positive"));
    expect(taxonomies(findings)).toContain("M9 — Unsafe/missing cache config");
  });

  it("does not flag the same page once it wraps the read in unstable_cache", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-config/negative"));
    expect(taxonomies(findings)).not.toContain("M9 — Unsafe/missing cache config");
  });

  it("does not flag a page that reads cookies() and queries the DB — dynamic by construction, no cache config expected", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-config/negative-dynamic-route"));
    expect(taxonomies(findings)).not.toContain("M9 — Unsafe/missing cache config");
    // still correctly flagged as dynamic rendering — that's the real signal here
    expect(taxonomies(findings)).toContain("M9 — Accidental dynamic rendering");
  });

  it("does not flag an auth-gated page that checks the caller's session before querying (#231)", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-config/negative-auth-page"));
    expect(taxonomies(findings)).not.toContain("M9 — Unsafe/missing cache config");
  });

  it("does not flag a token-gated route (reset-password, invite, callback, ...) even with no explicit auth check in the file (#231)", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-config/negative-token-route"));
    expect(taxonomies(findings)).not.toContain("M9 — Unsafe/missing cache config");
  });
});

describe("data-fetching waterfalls (MED, best-effort)", () => {
  it("flags two independent sequential DB awaits in an async Server Component", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall/positive"));
    const hits = findings.filter((f) => f.taxonomy === "M9 — Data-fetching waterfall");

    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("teams");
    expect(hits[0]?.evidence).toContain("projects");
  });

  it("does not flag the same queries once combined with Promise.all", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall/negative"));
    expect(taxonomies(findings)).not.toContain("M9 — Data-fetching waterfall");
  });

  it("does not flag a second query that depends on the first query's result", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall/negative-dependent"));
    expect(taxonomies(findings)).not.toContain("M9 — Data-fetching waterfall");
  });
});

describe("accidental dynamic rendering (MED, best-effort)", () => {
  it("flags a page that reads a searchParams field directly at the top level", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("dynamic-rendering/positive"));
    expect(taxonomies(findings)).toContain("M9 — Accidental dynamic rendering");
  });

  it("does not flag a page that only forwards searchParams to a Suspense-wrapped leaf", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("dynamic-rendering/negative"));
    expect(taxonomies(findings)).not.toContain("M9 — Accidental dynamic rendering");
  });

  it("flags a direct headers()/cookies()/noStore() call in a page module", () => {
    const findings = detectAppRouterFindings([
      { path: "app/account/page.tsx", text: `import { cookies } from "next/headers";\n\nexport default function AccountPage() {\n  const session = cookies().get("session");\n  return <p>{session?.value}</p>;\n}\n` },
    ]);
    const hits = findings.filter((f) => f.taxonomy === "M9 — Accidental dynamic rendering");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("cookies()");
  });
});

const SSR_API = "M9 — SSR-only API misuse";

// #381. `window`/`document`/`localStorage`/... read on the SSR render path crashes or
// hydration-mismatches. The FP boundary is the two standard safe idioms: a useEffect/handler
// (deferred, browser-only) and a `typeof window` guard.
describe("SSR-only browser API misuse (#381)", () => {
  it("flags a Server Component that reads window.innerWidth directly in its render body", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-browser-api/positive"));
    const hits = findings.filter((f) => f.taxonomy === SSR_API);

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Low", location: "app/page.tsx:3" });
    expect(hits[0]?.evidence).toContain("window.innerWidth");
  });

  it("does not flag browser-API reads inside a useEffect callback in a 'use client' component", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-browser-api/negative-effect"));
    expect(taxonomies(findings)).not.toContain(SSR_API);
  });

  it("does not flag reads guarded by `typeof window/localStorage !== 'undefined'`", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-browser-api/negative-typeof"));
    expect(taxonomies(findings)).not.toContain(SSR_API);
  });

  it("does not flag a browser-API read inside a class method (e.g. a Lexical node's client-only createDOM)", () => {
    // Measured FP on proposit: Lexical DecoratorNode.createDOM reads document.createElement but is
    // a client-only lifecycle method, not the App Router render path. Class members are off-path.
    const findings = detectAppRouterFindings([
      {
        path: "components/editor/nodes/ImageNode.tsx",
        text: `import { DecoratorNode } from "lexical";\nexport class ImageNode extends DecoratorNode<JSX.Element> {\n  createDOM(): HTMLElement {\n    return document.createElement("span");\n  }\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain(SSR_API);
  });

  it("does not flag a property access on a local variable that shadows a browser global", () => {
    // `document` here is a DB record, not the DOM global — the shadow check keeps it silent.
    const findings = detectAppRouterFindings([
      {
        path: "app/report/page.tsx",
        text: `export default async function Page() {\n  const document = await db.from("documents").select("*").single();\n  return <div>{document.title}</div>;\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain(SSR_API);
  });
});

describe("id assignment", () => {
  it("assigns sequential, unique M9-NN ids across all checks in a single run", () => {
    const findings = detectAppRouterFindings([
      ...loadFixtureDir("server-client-leak/positive"),
      ...loadFixtureDir("missing-server-only/positive"),
    ]);
    const ids = findings.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.every((id) => /^M9-\d{2}$/.test(id))).toBe(true);
  });
});
