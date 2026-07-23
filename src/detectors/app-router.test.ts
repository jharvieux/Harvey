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
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID_NOAUTH);
  });
});

const CLIENT_OWNER_ID_NOAUTH = "M1 — Client-supplied owner id trusted by unauthenticated service-role action";
const MISSING_AUTH = "M1 — Server Action missing authorization check";

// #465 widening (operator ruling): the three shapes proposit's real instances take — bare-id,
// INSERT-value, and no-in-body-auth — fire when (and only when) the chain roots in the
// RLS-bypassing service/admin client. Measured against proposit HEAD, 286 source files:
// recall 3/3 on the #221-catalogued instances, 0 false positives, and the RLS-client near-miss
// (updateOrganisationLogo) stays on the generic missing-auth finding.
describe("client-supplied owner id — widened service-role shapes (#465)", () => {
  it("flags a no-auth service-role mutation scoped by a bare client-supplied `id`, subsuming the generic missing-auth finding", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/positive-svc-bareid"));
    const hits = findings.filter((f) => f.taxonomy === CLIENT_OWNER_ID_NOAUTH);

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security", confidence: "Likely", precisionTier: "review" });
    expect(hits[0]?.title).toContain("updateUserProfile");
    expect(hits[0]?.title).toContain("with no auth check");
    // Dedupe (#465): one code defect, one finding — the generic missing-auth finding for the
    // SAME action is subsumed by this more specific one.
    expect(taxonomies(findings)).not.toContain(MISSING_AUTH);
  });

  it("flags a no-auth service-role insert whose owner column value is client-supplied (INSERT-value shape), subsuming missing-auth", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/positive-svc-insert"));
    const hits = findings.filter((f) => f.taxonomy === CLIENT_OWNER_ID_NOAUTH);

    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("addMember");
    expect(hits[0]?.evidence).toContain("user_id");
    expect(taxonomies(findings)).not.toContain(MISSING_AUTH);
  });

  it("does not flag the same bare-id syntax on the plain RLS client — the generic missing-auth finding fires instead, unsubsumed", () => {
    // proposit's updateOrganisationLogo, the measured near-miss: row policies still gate the
    // write, so the owner-id class stays silent and the defect stays one (generic) finding.
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/negative-rls-bareid"));
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID_NOAUTH);
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
    expect(taxonomies(findings)).toContain(MISSING_AUTH);
  });

  it("does not flag a service-role insert whose owner id reads off the session", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/negative-svc-insert-session"));
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID_NOAUTH);
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
  });

  it("does not flag a token-exchange flow that compares the client id against a row the server fetched before writing", () => {
    // The comparison against a DB-bound value IS the authorization check (collectDbBoundNames);
    // without it this exact fixture is the positive-svc-insert shape.
    const findings = detectAppRouterFindings(loadFixtureDir("client-owner-id/negative-svc-compared-dbrow"));
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID_NOAUTH);
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

const UNBOUNDED = "M9 — Unbounded/self-calling route or edge fn";

// #843. The M9 brief's "unbounded / self-calling route or edge fn" surface: a route/edge handler
// that loops forever or fetches its own URL. Scoped to route.ts/pages-api/middleware/edge-runtime
// files; the FP boundary is a `while(true)` with a break (bounded) and a fetch to a DIFFERENT URL.
describe("unbounded / self-calling route or edge fn (#843)", () => {
  it("flags a `while(true)` loop with no break/return/throw in a route handler", () => {
    const findings = detectAppRouterFindings([
      { path: "app/api/sync/route.ts", text: `export async function GET() {\n  let n = 0;\n  while (true) {\n    n += 1;\n  }\n}\n` },
    ]);
    const hits = findings.filter((f) => f.taxonomy === UNBOUNDED);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Medium", category: "Performance" });
    expect(hits[0]?.title).toContain("Unbounded loop");
  });

  it("flags a `for(;;)` loop with no escape in an edge-runtime file", () => {
    const findings = detectAppRouterFindings([
      { path: "app/worker/handler.ts", text: `export const runtime = "edge";\nexport function handler() {\n  for (;;) {\n    doWork();\n  }\n}\n` },
    ]);
    expect(taxonomies(findings)).toContain(UNBOUNDED);
  });

  it("does not flag a `while(true)` loop that breaks (bounded by construction)", () => {
    const findings = detectAppRouterFindings([
      { path: "app/api/sync/route.ts", text: `export async function GET() {\n  while (true) {\n    const done = await step();\n    if (done) break;\n  }\n  return Response.json({ ok: true });\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(UNBOUNDED);
  });

  it("flags a route handler that fetches its own request URL", () => {
    const findings = detectAppRouterFindings([
      { path: "app/api/proxy/route.ts", text: `export async function GET(request: Request) {\n  return fetch(request.url);\n}\n` },
    ]);
    const hits = findings.filter((f) => f.taxonomy === UNBOUNDED);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("fetches its own request URL");
  });

  it("flags a self-fetch through `req.nextUrl`", () => {
    const findings = detectAppRouterFindings([
      { path: "middleware.ts", text: `export function middleware(req) {\n  return fetch(new URL("/api/x", req.nextUrl.origin));\n}\n` },
    ]);
    expect(taxonomies(findings)).toContain(UNBOUNDED);
  });

  it("does not flag a fetch to a different, unrelated URL", () => {
    const findings = detectAppRouterFindings([
      { path: "app/api/proxy/route.ts", text: `export async function GET() {\n  return fetch("https://upstream.example.com/data");\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(UNBOUNDED);
  });

  it("does not flag an unbounded loop outside a route/edge handler (ordinary module code)", () => {
    const findings = detectAppRouterFindings([
      { path: "lib/util.ts", text: `export function loop() {\n  while (true) {\n    tick();\n  }\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(UNBOUNDED);
  });
});

// #844. The three Supabase-shaped data-layer checks silently no-op on Prisma/Drizzle targets. On a
// recognized non-Supabase data layer they must emit an explicit not-assessed row per check.
describe("non-Supabase data-layer coverage (#844)", () => {
  const DATA_LAYER_TAX = [
    "M9 — Server→client data leak — not assessed",
    "M9 — Unsafe/missing cache config — not assessed",
    "M9 — Data-fetching waterfall — not assessed",
  ];

  it("emits a not-assessed row for each data-layer check on a Prisma target", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-client-leak/positive"), "next", [], "prisma");
    for (const tax of DATA_LAYER_TAX) {
      const hits = findings.filter((f) => f.taxonomy === tax);
      expect(hits, tax).toHaveLength(1);
      expect(hits[0]).toMatchObject({ severity: "Info", confidence: "N/A", precisionTier: "high" });
      expect(hits[0]?.evidence).toContain("Prisma");
    }
    // The Supabase-shaped leak finding is suppressed — it would be a false clean, not a real result.
    expect(taxonomies(findings)).not.toContain("M9 — Server→client data leak");
  });

  it("names Drizzle from package.json when detectOrm reports unknown", () => {
    const findings = detectAppRouterFindings(
      [
        { path: "package.json", text: `{"dependencies":{"drizzle-orm":"^0.30.0","next":"14.0.0"}}` },
        { path: "app/dashboard/page.tsx", text: `export default function Page() { return <div/>; }` },
      ],
      "next",
      [],
      "unknown",
    );
    const hits = findings.filter((f) => f.taxonomy === "M9 — Server→client data leak — not assessed");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("Drizzle");
  });

  it("runs the real Supabase-shaped checks (no not-assessed rows) on a Supabase target", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-client-leak/positive"), "next", [], "supabase");
    expect(taxonomies(findings)).toContain("M9 — Server→client data leak");
    for (const tax of DATA_LAYER_TAX) expect(taxonomies(findings)).not.toContain(tax);
  });

  it("does not emit not-assessed rows on an unknown/no-DB target (avoids noise)", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-client-leak/positive"), "next", [], "unknown");
    for (const tax of DATA_LAYER_TAX) expect(taxonomies(findings)).not.toContain(tax);
    expect(taxonomies(findings)).toContain("M9 — Server→client data leak");
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

// #575: M9's checks are all Next.js-App-Router-specific. On a Vite/SPA target there is no SSR
// render path, so `detectSsrBrowserApiMisuse` (and the rest of the family) false-fires. When the
// framework probe (#573) says `vite`, the whole pass is suppressed to a single N/A coverage note.
const NON_SSR_NOTE = "M9 — Not applicable (non-Next SPA)";

describe("non-Next (Vite/SPA) framework gate (#575)", () => {
  it("suppresses all SSR/App-Router findings and emits one N/A note on a `vite` target", () => {
    // Same fixture that fires an SSR-misuse finding on Next (asserted above) — proving the
    // suppression is the framework gate, not an empty input.
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-browser-api/positive"), "vite");

    expect(taxonomies(findings)).not.toContain(SSR_API);
    expect(taxonomies(findings)).toEqual([NON_SSR_NOTE]);
    expect(findings[0]).toMatchObject({ severity: "Info", confidence: "N/A", id: "M9-01" });
    expect(findings[0]?.evidence).toContain("vite");
  });

  it("also suppresses M9's security findings (server→client leak, server actions) on a `vite` target", () => {
    const findings = detectAppRouterFindings(
      [...loadFixtureDir("server-client-leak/positive"), ...loadFixtureDir("missing-server-only/positive")],
      "vite",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.taxonomy).toBe(NON_SSR_NOTE);
  });

  it("leaves a Next App Router target unchanged — `next` behaves exactly like an omitted framework", () => {
    const fixture = loadFixtureDir("ssr-browser-api/positive");
    const explicitNext = detectAppRouterFindings(fixture, "next");
    const omitted = detectAppRouterFindings(fixture);

    expect(explicitNext).toEqual(omitted);
    expect(taxonomies(explicitNext)).toContain(SSR_API);
    expect(taxonomies(explicitNext)).not.toContain(NON_SSR_NOTE);
  });

  it("does NOT suppress on `other` (ambiguous shape) — only a confirmed non-SSR SPA is N/A", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-browser-api/positive"), "other");
    expect(taxonomies(findings)).toContain(SSR_API);
    expect(taxonomies(findings)).not.toContain(NON_SSR_NOTE);
  });
});

// #597: at a MONOREPO root the root's own verdict is `other` (vite.config lives in apps/web, not the
// root), so the whole-target `vite` short-circuit above never fires and the SSR family false-fires
// on the Vite app's files — the #575 regression. The gate takes the Vite workspace dirs and
// suppresses the family per-app: files under a Vite workspace get one N/A note; every other file
// (including a genuine Next workspace's) still runs the full pass.
function prefixPaths(files: SourceInput[], prefix: string): SourceInput[] {
  return files.map((f) => ({ ...f, path: `${prefix}/${f.path}` }));
}

describe("monorepo per-workspace framework gate (#597)", () => {
  it("suppresses the SSR family for a Vite workspace's files even when the root verdict is `other`", () => {
    const webFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/web");
    const findings = detectAppRouterFindings(webFiles, "other", ["apps/web"]);

    expect(taxonomies(findings)).not.toContain(SSR_API);
    expect(taxonomies(findings)).toContain(NON_SSR_NOTE);
    expect(findings.find((f) => f.taxonomy === NON_SSR_NOTE)?.location).toBe("apps/web");
  });

  it("keeps M9 active on a Next workspace in the same monorepo while the Vite workspace is N/A", () => {
    const webFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/web"); // Vite
    const apiFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/api"); // Next
    const findings = detectAppRouterFindings([...webFiles, ...apiFiles], "other", ["apps/web"]);

    // The Vite side is N/A; the Next side still fires SSR-misuse.
    expect(taxonomies(findings)).toContain(NON_SSR_NOTE);
    expect(taxonomies(findings)).toContain(SSR_API);
    const ssr = findings.filter((f) => f.taxonomy === SSR_API);
    expect(ssr.length).toBeGreaterThan(0);
    expect(ssr.every((f) => f.location.startsWith("apps/api/"))).toBe(true);
    expect(ssr.some((f) => f.location.startsWith("apps/web/"))).toBe(false);
  });

  it("emits no N/A note for a listed Vite workspace that contributes no files", () => {
    const apiFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/api");
    const findings = detectAppRouterFindings(apiFiles, "other", ["apps/web"]);
    expect(taxonomies(findings)).not.toContain(NON_SSR_NOTE);
    expect(taxonomies(findings)).toContain(SSR_API);
  });
});

// #627: a Vite/SPA has no framework-level error boundary (no Next error.tsx), so an entry that
// mounts the root with no error boundary anywhere blanks the whole app on an unhandled render
// error. This runs ONLY on the Vite/SPA scope the rest of the M9 pass is suppressed on.
const SPA_BOUNDARY = "M9 — SPA missing root error boundary";

describe("SPA root error-boundary absence (#627)", () => {
  it("flags a `vite` entry that mounts the root with no error boundary anywhere in the SPA", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("spa-error-boundary/positive"), "vite");
    const boundary = findings.filter((f) => f.taxonomy === SPA_BOUNDARY);
    expect(boundary).toHaveLength(1);
    expect(boundary[0]).toMatchObject({ severity: "Low", confidence: "Review", category: "Reliability" });
    expect(boundary[0]?.location).toBe("main.tsx:5");
    // The N/A coverage note still accompanies it — the family is still suppressed, this is the one
    // SPA-specific check that runs on the Vite scope.
    expect(taxonomies(findings)).toContain(NON_SSR_NOTE);
  });

  it("stays silent when the SPA already wraps the root in a boundary (react-error-boundary)", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("spa-error-boundary/negative-has-boundary"), "vite");
    expect(taxonomies(findings)).not.toContain(SPA_BOUNDARY);
    expect(taxonomies(findings)).toContain(NON_SSR_NOTE);
  });

  it("does NOT run on a Next/omitted-framework target — the check is Vite/SPA-specific", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("spa-error-boundary/positive"));
    expect(taxonomies(findings)).not.toContain(SPA_BOUNDARY);
  });

  it("flags a Vite workspace's entry in a monorepo, located under the workspace dir", () => {
    const webFiles = prefixPaths(loadFixtureDir("spa-error-boundary/positive"), "apps/web");
    const findings = detectAppRouterFindings(webFiles, "other", ["apps/web"]);
    const boundary = findings.filter((f) => f.taxonomy === SPA_BOUNDARY);
    expect(boundary).toHaveLength(1);
    expect(boundary[0]?.location).toBe("apps/web/main.tsx:5");
  });
});
