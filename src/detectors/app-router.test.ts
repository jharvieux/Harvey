import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
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
    for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) {
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

  // #847: the common real-world shape maps the row into an intermediate binding first. One hop of
  // alias/spread tracking must still flag it.
  const clientView: SourceInput = {
    path: "app/dashboard/ClientView.tsx",
    text: `"use client";\nexport function ClientView({ user }: { user: any }) { return <div>{user.name}</div>; }\n`,
  };

  it("flags a full row passed through an intermediate alias binding (`const dto = row`)", () => {
    const findings = detectAppRouterFindings([
      clientView,
      {
        path: "app/dashboard/page.tsx",
        text: `import { ClientView } from "./ClientView";\nexport default async function Page() {\n  const { data: user } = await db.from("users").select("*").single();\n  const dto = user;\n  return <ClientView user={dto} />;\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).toContain("M9 — Server→client data leak");
  });

  it("flags a full row passed through an inline object spread (`data={{...row}}`)", () => {
    const findings = detectAppRouterFindings([
      clientView,
      {
        path: "app/dashboard/page.tsx",
        text: `import { ClientView } from "./ClientView";\nexport default async function Page() {\n  const { data: user } = await db.from("users").select("*").single();\n  return <ClientView user={{...user}} />;\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).toContain("M9 — Server→client data leak");
  });

  it("flags a full row aliased through a spread binding (`const dto = {...row}`)", () => {
    const findings = detectAppRouterFindings([
      clientView,
      {
        path: "app/dashboard/page.tsx",
        text: `import { ClientView } from "./ClientView";\nexport default async function Page() {\n  const { data: user } = await db.from("users").select("*").single();\n  const dto = {...user};\n  return <ClientView user={dto} />;\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).toContain("M9 — Server→client data leak");
  });

  it("does not flag a narrowed destructure alias (`const { name } = row`)", () => {
    const findings = detectAppRouterFindings([
      clientView,
      {
        path: "app/dashboard/page.tsx",
        text: `import { ClientView } from "./ClientView";\nexport default async function Page() {\n  const { data: user } = await db.from("users").select("*").single();\n  const { name } = user;\n  return <ClientView user={name} />;\n}\n`,
      },
    ]);
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

  // #845: the auth/validation keywords are matched over the action's real code tokens, not the raw
  // text — a keyword in a comment or string literal no longer defeats the check.
  it("still flags missing auth when the only `auth`/parse keyword sits in a comment or string", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nexport async function updateBio(input: { bio: string }) {\n  // TODO: add auth check here\n  const label = "user must parse and authenticate";\n  await admin.from("profiles").update({ bio: input.bio });\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).toContain("M1 — Server Action missing authorization check");
    expect(taxonomies(findings)).toContain("M9 — Server Action missing input validation");
  });

  it("does not flag missing validation when a real .parse() call is present (comment stripping doesn't blank code)", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nimport { getCurrentUser } from "../lib/auth";\nimport { schema } from "../lib/schema";\nexport async function updateBio(input: unknown) {\n  const user = await getCurrentUser();\n  const data = schema.parse(input);\n  await admin.from("profiles").update({ bio: data.bio }).eq("user_id", user.id);\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain("M9 — Server Action missing input validation");
  });

  it("does not scope an action as mutating when `.update(` appears only in a string literal", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\nexport async function logNote(note: string) {\n  console.log(".update() was requested: " + note);\n}\n`,
      },
    ]);
    expect(findings).toEqual([]);
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

// #1051 — the OTHER cache failure mode briefs/audit-modules.md requires. The missing-config check
// above treats any cache signal as evidence of correctness, so before this the bleed case was
// suppressed by the very directive that causes it and the scan reported clean.
describe("cross-user cache bleed (HIGH)", () => {
  const BLEED = "M9 — Cross-user cache bleed";

  it("flags per-user data cached under a global key, a session read inside a `use cache` scope, and a public Cache-Control on an authenticated response", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-bleed/positive"));
    const bleeds = findings.filter((f) => f.taxonomy === BLEED);

    expect(bleeds).toHaveLength(3);
    for (const f of bleeds) expect(f).toMatchObject({ severity: "High", category: "Security" });
    expect(bleeds.map((f) => f.location).sort()).toEqual(["app/api/invoices/route.ts", "app/dashboard/page.tsx:6", "app/orders/page.tsx:7"]);
  });

  it("stays quiet when the identity is in the cache key, arrives as a `use cache` argument, or the response is private", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-bleed/negative"));
    expect(taxonomies(findings)).not.toContain(BLEED);
  });

  // The existing missing-config negative caches a non-user-specific `teams` list — it must stay a
  // true negative for BOTH cache checks, not trade one finding for the other.
  it("does not fire on the missing-cache-config negative (a cached read with nothing per-user about it)", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-config/negative"));
    expect(taxonomies(findings)).not.toContain(BLEED);
  });

  it("discloses a non-inline cached callback as not-assessed rather than dropping it", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/orders/page.tsx",
        text: `import { unstable_cache } from "next/cache";\nimport { loadOrders } from "../../lib/orders";\nconst cached = unstable_cache(loadOrders, ["orders"]);\nexport default async function Page() { return <div>{(await cached()).length}</div>; }\n`,
      },
    ]);
    const row = findings.find((f) => f.taxonomy === "M9 — Cross-user cache bleed — not assessed");

    expect(row, "the undecidable shape must be disclosed, not silently dropped").toBeDefined();
    expect(row).toMatchObject({ confidence: "N/A", location: "app/orders/page.tsx:3" });
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

  // #1081: the detector used to `break` after the first independent pair, so a third (or later)
  // independent await in the same function vanished with no count. One finding per function is
  // still correct (Promise.all-ing the whole function covers every pair) — this checks the dropped
  // pair count and its location now survive into evidence instead of disappearing silently.
  it("discloses additional independent pairs beyond the first instead of dropping them silently", () => {
    const text = `
      export default async function DashboardPage() {
        const { data: teams } = await supabase.from("teams").select("id");
        const { data: projects } = await supabase.from("projects").select("id");
        const { data: invoices } = await supabase.from("invoices").select("id");
        return <div>{teams?.length} {projects?.length} {invoices?.length}</div>;
      }
    `;
    const findings = detectAppRouterFindings([{ path: "app/dashboard/page.tsx", text }]);
    const hits = findings.filter((f) => f.taxonomy === "M9 — Data-fetching waterfall");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("first of 2 such pairs");
    expect(hits[0]?.evidence).toContain("invoices");
  });
});

const WATERFALL_TAX = "M9 — Data-fetching waterfall";
const WATERFALL_SCOPE = "M9 — Data-fetching waterfall — scope";

// #1438 — #1292's escape rule counted ANY Break/Continue node. One belonging to a `switch` or an
// inner loop inside the intervening statement leaves neither the function nor the path to the
// second query, so it suppressed a genuinely parallelisable pair.
describe("waterfall escape rule: which guards actually skip the second query (#1438)", () => {
  const PAGE = "app/dashboard/page.tsx";
  const pair = (between: string) =>
    `export default async function Page() {\n  const { data: rows } = await supabase.from("rows").select("id, status");\n${between}\n  const { data: projects } = await supabase.from("projects").select("id");\n  return null;\n}\n`;

  it("still flags the pair when an intervening switch's `break` belongs to that switch", () => {
    const findings = detectAppRouterFindings([{ path: PAGE, text: pair(`  switch (rows?.[0]?.status) {\n    case "open":\n      log(rows);\n      break;\n  }`) }]);
    expect(taxonomies(findings)).toContain(WATERFALL_TAX);
  });

  it("still flags the pair when an intervening inner loop's `break` belongs to that loop", () => {
    const findings = detectAppRouterFindings([{ path: PAGE, text: pair(`  for (const r of rows ?? []) {\n    if (r.active) {\n      note(r);\n      break;\n    }\n  }`) }]);
    expect(taxonomies(findings)).toContain(WATERFALL_TAX);
  });

  it("still flags the pair when a labelled `break` targets a label declared inside the statement", () => {
    const findings = detectAppRouterFindings([
      { path: PAGE, text: pair(`  outer: for (const r of rows ?? []) {\n    for (const c of r.children) {\n      if (c.id) break outer;\n    }\n  }`) },
    ]);
    expect(taxonomies(findings)).toContain(WATERFALL_TAX);
  });

  it("still suppresses on a `return` inside an intervening switch case — the rule was narrowed, not removed", () => {
    const findings = detectAppRouterFindings([{ path: PAGE, text: pair(`  switch (rows?.[0]?.status) {\n    case "archived":\n      return null;\n  }`) }]);
    expect(taxonomies(findings)).not.toContain(WATERFALL_TAX);
  });

  it("still suppresses on a plain early return", () => {
    const findings = detectAppRouterFindings([{ path: PAGE, text: pair(`  if (!rows) return null;`) }]);
    expect(taxonomies(findings)).not.toContain(WATERFALL_TAX);
  });

  // The corpus entry M9C-WATERFALL-ESCAPE-POS scores one fixture dir carrying BOTH shapes, and a
  // `match` key is satisfied by any one finding — so on its own the entry would stay green with
  // half the fix reverted. The count is what makes it discriminate: one finding per function, two
  // functions, so either shape going silent drops it to 1.
  it("the committed positive fixture yields ONE finding per shape, so neither can regress under the other", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall-escape/positive"));
    const hits = findings.filter((f) => f.taxonomy === WATERFALL_TAX);
    expect(hits).toHaveLength(2);
    expect(hits.map((f) => f.evidence).join(" ")).toContain("projects");
    expect(hits.map((f) => f.evidence).join(" ")).toContain("invoices");
  });

  it("does not flag the pair on the strength of a break inside a nested function — that break is not even reachable from here", () => {
    // A `break` inside a nested arrow is a syntax error unless it has its own loop; the point of the
    // control is that walking into the arrow must not change the verdict either way.
    const findings = detectAppRouterFindings([{ path: PAGE, text: pair(`  const first = (rows ?? []).find((r) => {\n    for (const c of r.children) { if (c.id) break; }\n    return true;\n  });`) }]);
    expect(taxonomies(findings)).toContain(WATERFALL_TAX);
  });
});

// #1441 — the #1292 suppression is one rule over two different control-flow facts, and one of the
// two is a recall loss. Plus the disclosure the trade always owed the client.
describe("waterfall: aborting guards, and the scope row that counts what is set aside (#1441)", () => {
  const PAGE = "app/dashboard/page.tsx";
  const READ_THEN_READ = `export default async function Page() {\n  const { data: price } = await supabase.from("prices").select("id").single();\n  if (!price) throw new Error("no price");\n  const { data: sub } = await supabase.from("subscriptions").select("id").eq("user_id", userId).maybeSingle();\n  return null;\n}\n`;

  it("flags two READS separated by an error-only guard — the request ends, so nothing observes the second result", () => {
    const findings = detectAppRouterFindings([{ path: PAGE, text: READ_THEN_READ }]);
    expect(taxonomies(findings)).toContain(WATERFALL_TAX);
  });

  it("treats `throw redirect(...)` the same way — it aborts the request, it does not skip the query", () => {
    const text = `export default async function Page() {\n  const existing = await client.from("depreciationRun").select("id").eq("companyId", companyId);\n  if (existing.data?.length) throw redirect(path.to.runs);\n  const settings = await client.from("companySettings").select("taxEnabled").single();\n  return null;\n}\n`;
    expect(taxonomies(detectAppRouterFindings([{ path: PAGE, text }]))).toContain(WATERFALL_TAX);
  });

  it("does NOT flag when the second statement writes — `.from(x).update(...).select(...)` passes isDbQueryChain but is a write", () => {
    const text = `export default async function Page() {\n  const { data: current } = await supabase.from("receipt").select("status").eq("id", id).single();\n  if (current?.status === "Voided") throw new Error("voided");\n  const applied = await supabase.from("receipt").update({ status: "Pending" }).eq("id", id).select("id");\n  return applied;\n}\n`;
    expect(taxonomies(detectAppRouterFindings([{ path: PAGE, text }]))).not.toContain(WATERFALL_TAX);
  });

  it("keeps walking past an aborting guard, so a LATER diverting guard still suppresses", () => {
    const text = `export default async function Page() {\n  const { data: invitation } = await supabase.from("invitations").select("id, status").single();\n  if (!invitation) throw new Error("not found");\n  if (invitation.status !== "pending") return null;\n  const { data: account } = await supabase.from("accounts").select("id").eq("id", accountId).single();\n  return null;\n}\n`;
    expect(taxonomies(detectAppRouterFindings([{ path: PAGE, text }]))).not.toContain(WATERFALL_TAX);
  });

  it("keeps walking past an aborting guard, so taint laundered into a LATER binding still suppresses", () => {
    const text = `export default async function Page() {\n  const { data: invitation } = await supabase.from("invitations").select("id, email").single();\n  if (!invitation) throw new Error("not found");\n  const email = invitation.email.trim();\n  const { data: account } = await supabase.from("accounts").select("id").eq("email", email).single();\n  return null;\n}\n`;
    expect(taxonomies(detectAppRouterFindings([{ path: PAGE, text }]))).not.toContain(WATERFALL_TAX);
  });

  it("emits a counted scope row naming the excluded class WITH its population", () => {
    const text = `export default async function Page() {\n  const { data: team } = await supabase.from("teams").select("id").single();\n  if (!team) return null;\n  const { data: settings } = await supabase.from("settings").select("theme").single();\n  return null;\n}\n`;
    const findings = detectAppRouterFindings([{ path: PAGE, text }]);
    const row = findings.find((f) => f.taxonomy === WATERFALL_SCOPE);
    expect(row, "a suppressed pair must produce a scope row").toBeDefined();
    expect(row?.confidence).toBe("N/A");
    expect(row?.title).toContain("1 of 1 adjacent query pair excluded by policy");
    expect(row?.evidence).toContain("1 pair is separated by a guard");
    // The finding itself is gone; without this row the report reads as a clean M9 waterfall result.
    expect(taxonomies(findings)).not.toContain(WATERFALL_TAX);
  });

  it("emits NO scope row when nothing was set aside — the family discloses limitations, not statuses", () => {
    const text = `export default async function Page() {\n  const { data: teams } = await supabase.from("teams").select("id");\n  const { data: projects } = await supabase.from("projects").select("id");\n  return null;\n}\n`;
    const findings = detectAppRouterFindings([{ path: PAGE, text }]);
    expect(taxonomies(findings)).toContain(WATERFALL_TAX);
    expect(taxonomies(findings)).not.toContain(WATERFALL_SCOPE);
  });
});

// #1439 — #1263 taught the gate check to resolve a callee and re-test the auth/validation pattern
// against its body. Matching the pattern says the helper LOOKS at the session; it does not say the
// helper can stop the mutation.
describe("Server Action gate resolution: a resolved callee must be able to deny (#1439)", () => {
  const AUTHZ = "M1 — Server Action missing authorization check";

  it("does not accept a LOGGER as a gate, however much its body reads the session", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("action-gate-strength/positive"));
    const hits = findings.filter((f) => f.taxonomy === AUTHZ);
    expect(hits.map((f) => f.title).join(" ")).toContain("renameLogged");
  });

  it("does not accept a boolean gate whose result is discarded", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("action-gate-strength/positive"));
    const hits = findings.filter((f) => f.taxonomy === AUTHZ);
    expect(hits.map((f) => f.title).join(" ")).toContain("renameUnchecked");
    expect(hits).toHaveLength(2);
  });

  it("accepts the same boolean gate once a branch consumes it", () => {
    const action = `"use server";\nimport { canAccess } from "../lib/access";\nimport { supabase } from "../lib/db";\nexport async function rename(id: string, name: string) {\n  const allowed = await canAccess(id);\n  if (!allowed) return;\n  await supabase.from("projects").update({ name }).eq("id", id);\n}\n`;
    const helper = `import { supabase } from "./db";\nexport async function canAccess(id: string) {\n  const { data: { user } } = await supabase.auth.getUser();\n  return user?.id === id;\n}\n`;
    const findings = detectAppRouterFindings([
      { path: "app/actions.ts", text: action },
      { path: "lib/access.ts", text: helper },
    ]);
    expect(taxonomies(findings)).not.toContain(AUTHZ);
  });

  it("resolves a NAMESPACE-imported gate, so `guards.ensureMember(id)` stops false-firing", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("action-gate-strength/negative"));
    expect(taxonomies(findings)).not.toContain(AUTHZ);
  });

  it("still resolves the named-import gate #1263 shipped — the namespace path is an addition, not a swap", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-helper-gate/negative"));
    expect(taxonomies(findings)).not.toContain(AUTHZ);
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

  // #964: at carbon's scale (RR7 monorepo) the "any free function is a render body" heuristic
  // false-fired on 59 non-component `.ts` utilities. A component needs JSX, so it can only live in
  // a `.tsx`/`.jsx` module — a function in a plain `.ts` service file is not a render body.
  it("does not flag a browser-global read inside a function in a non-component `.ts` util file", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/components/Configurator/utils.ts",
        text: `export function convertTypescriptToJavaScript(src: string) {\n  if (window?.ts) {\n    return window.ts.transpile(src);\n  }\n  return src;\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain(SSR_API);
  });

  // #964: module-top-level code in a `.ts` file DOES run during SSR on import, so it must stay
  // flagged — the fix scopes function bodies, it does not blanket-suppress `.ts`.
  it("still flags a browser-global read at module top level of a `.ts` file", () => {
    const findings = detectAppRouterFindings([
      { path: "lib/theme.ts", text: `export const width = window.innerWidth;\n` },
    ]);
    expect(taxonomies(findings)).toContain(SSR_API);
  });

  // #964: optional-chaining a browser global (`window?.x`) is the author's explicit absent-guard —
  // even in a `.tsx` component render body it must not fire.
  it("does not flag an optional-chained browser-global read (`window?.x`) in a component body", () => {
    const findings = detectAppRouterFindings([
      { path: "app/screen.tsx", text: `export default function Screen() {\n  const w = window?.innerWidth ?? 0;\n  return <div>{w}</div>;\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(SSR_API);
  });

  // #964: an inner unguarded read (`window.ts`) is still safe when an enclosing `if (window?.ts)`
  // optional-chaining guard gates it.
  it("does not flag a read gated by an enclosing `if (window?.x)` optional-chaining guard", () => {
    const findings = detectAppRouterFindings([
      { path: "app/widget.tsx", text: `export default function Widget() {\n  if (window?.ts) {\n    return <div>{window.ts.version}</div>;\n  }\n  return null;\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(SSR_API);
  });
});

const SEGMENT_CFG = "M9 — Unsafe route segment config";
const SEGMENT_CONFLICT = "M9 — Conflicting route segment config";
const MISSING_SUSPENSE = "M9 — Missing Suspense boundary";

// #846. Route segment config (dynamic/revalidate/...) is now validated, plus a missing-Suspense
// check around dynamic reads.
describe("route segment config & missing Suspense (#846)", () => {
  it("flags force-static on a route that reads a dynamic API", () => {
    const findings = detectAppRouterFindings([
      { path: "app/dashboard/page.tsx", text: `import { cookies } from "next/headers";\nexport const dynamic = "force-static";\nexport default function Page() {\n  const t = cookies().get("session");\n  return <div>{t?.value}</div>;\n}\n` },
    ]);
    const hits = findings.filter((f) => f.taxonomy === SEGMENT_CFG);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security" });
  });

  it("flags force-static on an auth-gated route", () => {
    const findings = detectAppRouterFindings([
      { path: "app/account/page.tsx", text: `import { getServerSession } from "next-auth";\nexport const dynamic = "force-static";\nexport default async function Page() {\n  const session = await getServerSession();\n  return <div>{session?.user?.name}</div>;\n}\n` },
    ]);
    expect(taxonomies(findings)).toContain(SEGMENT_CFG);
  });

  it("does not flag force-static on a plain public/static page", () => {
    const findings = detectAppRouterFindings([
      { path: "app/about/page.tsx", text: `export const dynamic = "force-static";\nexport default function Page() {\n  return <div>About us</div>;\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(SEGMENT_CFG);
  });

  it("flags force-dynamic combined with a positive revalidate (dead config)", () => {
    const findings = detectAppRouterFindings([
      { path: "app/feed/page.tsx", text: `export const dynamic = "force-dynamic";\nexport const revalidate = 3600;\nexport default function Page() {\n  return <div/>;\n}\n` },
    ]);
    expect(taxonomies(findings)).toContain(SEGMENT_CONFLICT);
  });

  it("flags force-static combined with revalidate = 0 (contradiction)", () => {
    const findings = detectAppRouterFindings([
      { path: "app/feed/page.tsx", text: `export const dynamic = "force-static";\nexport const revalidate = 0;\nexport default function Page() {\n  return <div/>;\n}\n` },
    ]);
    expect(taxonomies(findings)).toContain(SEGMENT_CONFLICT);
  });

  it("does not flag a coherent revalidate-only config", () => {
    const findings = detectAppRouterFindings([
      { path: "app/feed/page.tsx", text: `export const revalidate = 60;\nexport default function Page() {\n  return <div/>;\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(SEGMENT_CONFLICT);
    expect(taxonomies(findings)).not.toContain(SEGMENT_CFG);
  });

  it("flags a page that reads a dynamic API and fetches data with no <Suspense> boundary", () => {
    const findings = detectAppRouterFindings([
      { path: "app/feed/page.tsx", text: `import { cookies } from "next/headers";\nexport default async function Page() {\n  const t = cookies().get("t");\n  const data = await fetch("https://api.example.com/feed");\n  return <div>{t?.value}</div>;\n}\n` },
    ]);
    expect(taxonomies(findings)).toContain(MISSING_SUSPENSE);
  });

  it("does not flag a missing Suspense boundary when one is present", () => {
    const findings = detectAppRouterFindings([
      { path: "app/feed/page.tsx", text: `import { Suspense } from "react";\nimport { cookies } from "next/headers";\nexport default async function Page() {\n  const t = cookies().get("t");\n  const data = await fetch("https://api.example.com/feed");\n  return <Suspense fallback={null}><div>{t?.value}</div></Suspense>;\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(MISSING_SUSPENSE);
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

const RETRY = "M9 — Uncapped retry/fan-out";
const RETRY_SCOPE = "M9 — Uncapped retry/fan-out — scope";

// #1262 (#843 remainder). The brief's third unbounded-route shape, which shipped neither as a
// detector nor as a disclosure row. Two AST shapes plus a counted scope row.
describe("uncapped retry / fan-out (#1262)", () => {
  const ROUTE = "app/api/sync/route.ts";

  it("flags a retry loop whose attempt count comes from the request", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function POST(request: Request) {\n  const { url, attempts } = await request.json();\n  for (let i = 0; i < attempts; i++) {\n    try {\n      return await fetch(url);\n    } catch {}\n  }\n}\n` },
    ]);
    const hits = findings.filter((f) => f.taxonomy === RETRY);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Medium", category: "Performance" });
    expect(hits[0]?.evidence).toContain("i < attempts");
  });

  it("flags a `while (true)` retry whose only escape is the success path", () => {
    // The sibling #843 check stays silent here — the `return` counts as an escape for it — so this
    // shape had no detector at all before #1262.
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function GET() {\n  while (true) {\n    try {\n      return await fetch("https://upstream.example.com/x");\n    } catch {}\n  }\n}\n` },
    ]);
    expect(taxonomies(findings)).toContain(RETRY);
    expect(taxonomies(findings)).not.toContain(UNBOUNDED);
  });

  // #1440 — the canonical uncapped retry. `retryLoopIsUncapped` accepted only a literal-`true`
  // while-condition, so this was never assessed AND was not named in the scope row that exists to
  // name unassessed classes.
  it("flags the canonical `while (!done)` retry whose catch swallows", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function POST(request: Request) {\n  const { url } = await request.json();\n  let done = false;\n  while (!done) {\n    try {\n      await fetch(url);\n      done = true;\n    } catch {}\n  }\n}\n` },
    ]);
    const hits = findings.filter((f) => f.taxonomy === RETRY);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("!done");
  });

  it("does not flag a while-retry whose counter is compared against a numeric const", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `const MAX = 5;\nexport async function GET() {\n  let n = 0;\n  while (n < MAX) {\n    n += 1;\n    try {\n      return await fetch("https://u.example.com/x");\n    } catch {}\n  }\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(RETRY);
  });

  it("reads `&&` as capped when EITHER side caps, and `||` only when both do", () => {
    const capped = detectAppRouterFindings([
      { path: ROUTE, text: `export async function GET() {\n  let n = 0, done = false;\n  while (!done && n < 3) {\n    n += 1;\n    try {\n      return await fetch("https://u.example.com/x");\n    } catch {}\n  }\n}\n` },
    ]);
    expect(taxonomies(capped)).not.toContain(RETRY);
    const uncapped = detectAppRouterFindings([
      { path: ROUTE, text: `export async function GET() {\n  let n = 0, done = false;\n  while (!done || n < 3) {\n    n += 1;\n    try {\n      return await fetch("https://u.example.com/x");\n    } catch {}\n  }\n}\n` },
    ]);
    expect(taxonomies(uncapped)).toContain(RETRY);
  });

  it("states the bound it actually read — the header, not the body", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function GET() {\n  let done = false;\n  while (!done) {\n    try {\n      await fetch("https://u.example.com/x");\n      done = true;\n    } catch {}\n  }\n}\n` },
    ]);
    expect(findings.find((f) => f.taxonomy === RETRY)?.evidence).toContain("reads the loop HEADER only");
  });

  it("names the header-only bound in the scope row, with its count", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function GET() {\n  let done = false;\n  while (!done) {\n    try {\n      await fetch("https://u.example.com/x");\n      done = true;\n    } catch {}\n  }\n}\n` },
    ]);
    const row = findings.find((f) => f.taxonomy === RETRY_SCOPE);
    expect(row?.evidence).toContain("FOUR sub-shapes");
    expect(row?.evidence).toContain("1 of the retry loops reported above has a non-literal header");
  });

  it("does not count a `while (true)` retry as a header-only bound — its header IS the whole story", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function GET() {\n  while (true) {\n    try {\n      return await fetch("https://u.example.com/x");\n    } catch {}\n  }\n}\n` },
    ]);
    expect(findings.find((f) => f.taxonomy === RETRY_SCOPE)?.evidence).toContain("0 of the retry loops reported above have a non-literal header");
  });

  it("does not flag a retry capped by a numeric literal or a numeric const", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `const MAX = 3;\nexport async function GET() {\n  for (let i = 0; i < MAX; i++) {\n    try {\n      return await fetch("https://u.example.com/x");\n    } catch {}\n  }\n  for (let j = 0; j < 5; j++) {\n    try {\n      return await fetch("https://u.example.com/y");\n    } catch {}\n  }\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(RETRY);
  });

  it("does not flag an uncapped loop with no catch (not a retry) or with no outbound call", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function GET(request: Request) {\n  const { n } = await request.json();\n  for (let i = 0; i < n; i++) {\n    await fetch("https://u.example.com/x");\n  }\n  for (let j = 0; j < n; j++) {\n    try {\n      compute(j);\n    } catch {}\n  }\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(RETRY);
  });

  it("flags a Promise.all fan-out over a request-supplied collection", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function POST(request: Request) {\n  const { ids } = await request.json();\n  const out = await Promise.all(ids.map((id) => fetch("https://u.example.com/" + id)));\n  return Response.json(out.length);\n}\n` },
    ]);
    const hits = findings.filter((f) => f.taxonomy === RETRY);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("`ids`");
  });

  it("does not flag a sliced fan-out, nor one over a collection the server sized", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `export async function POST(request: Request) {\n  const { ids } = await request.json();\n  await Promise.all(ids.slice(0, 20).map((id) => fetch("https://u.example.com/" + id)));\n  const { data: rows } = await supabase.from("jobs").select("id");\n  await Promise.all(rows.map((r) => fetch("https://u.example.com/" + r.id)));\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(RETRY);
  });

  it("does not flag either shape outside a route/edge handler", () => {
    const findings = detectAppRouterFindings([
      { path: "lib/sync.ts", text: `export async function sync(request) {\n  const { attempts } = await request.json();\n  for (let i = 0; i < attempts; i++) {\n    try {\n      return await fetch("https://u.example.com/x");\n    } catch {}\n  }\n}\n` },
    ]);
    expect(taxonomies(findings)).not.toContain(RETRY);
  });

  // The disclosure half: what the two shapes do not reach must be stated, with counts, whenever the
  // target has route/edge handlers at all — silence there reads as a clean bill of health.
  it("emits a counted scope row naming the three unassessed sub-shapes", () => {
    const findings = detectAppRouterFindings([
      { path: ROUTE, text: `import pRetry from "p-retry";\nexport async function GET() {\n  const { data: rows } = await supabase.from("jobs").select("id");\n  await Promise.all(rows.map((r) => fetch("https://u.example.com/" + r.id)));\n  return pRetry(() => fetch("https://u.example.com/x"));\n}\n` },
    ]);
    const rows = findings.filter((f) => f.taxonomy === RETRY_SCOPE);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ severity: "Info", confidence: "N/A", precisionTier: "high", location: "(whole target)" });
    // The counts are the population — a bound with a population of zero is a guess, not a limit.
    expect(rows[0]?.evidence).toContain("1 route/edge handler was checked");
    expect(rows[0]?.evidence).toContain("1 handler file imports one");
    expect(rows[0]?.evidence).toContain("1 such site");
    expect(rows[0]?.evidence).toContain("RECURSION");
  });

  it("emits no scope row on a target with no route/edge handlers", () => {
    const findings = detectAppRouterFindings([{ path: "lib/util.ts", text: `export const x = 1;\n` }]);
    expect(taxonomies(findings)).not.toContain(RETRY_SCOPE);
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

  // #861 (the #844 remainder): a raw-SQL target has no ORM dependency at all, so the checks used to
  // find nothing AND say nothing. The declared driver dependency is the positive signal.
  it("names the raw-SQL driver on a `pg` target with no ORM dependency", () => {
    const findings = detectAppRouterFindings(
      [
        { path: "package.json", text: `{"dependencies":{"pg":"^8.11.0","next":"14.0.0"}}` },
        { path: "app/dashboard/page.tsx", text: `export default function Page() { return <div/>; }` },
      ],
      "next",
      [],
      "unknown",
    );
    for (const tax of DATA_LAYER_TAX) {
      const hits = findings.filter((f) => f.taxonomy === tax);
      expect(hits, tax).toHaveLength(1);
      expect(hits[0]?.evidence).toContain("raw SQL (pg)");
    }
  });

  it("names postgres.js as the raw-SQL driver too", () => {
    const findings = detectAppRouterFindings(
      [
        { path: "package.json", text: `{"dependencies":{"postgres":"^3.4.0"}}` },
        { path: "app/dashboard/page.tsx", text: `export default function Page() { return <div/>; }` },
      ],
      "next",
      [],
      "unknown",
    );
    expect(findings.find((f) => f.taxonomy === DATA_LAYER_TAX[0])?.evidence).toContain("raw SQL (postgres)");
  });

  it("keeps the real checks on a Supabase app that also ships a raw-SQL driver (#861 precedence)", () => {
    const findings = detectAppRouterFindings(
      [
        { path: "package.json", text: `{"dependencies":{"@supabase/supabase-js":"^2.45.0","pg":"^8.12.0"}}` },
        ...loadFixtureDir("server-client-leak/positive"),
      ],
      "next",
    );
    for (const tax of DATA_LAYER_TAX) expect(taxonomies(findings)).not.toContain(tax);
    expect(taxonomies(findings)).toContain("M9 — Server→client data leak");
  });

  it("still emits nothing for a DB-less app whose package.json declares no driver (#861 no-false-fire)", () => {
    const findings = detectAppRouterFindings(
      [
        { path: "package.json", text: `{"dependencies":{"next":"14.0.0","react":"^18.0.0"}}` },
        { path: "app/dashboard/page.tsx", text: `export default function Page() { return <div/>; }` },
      ],
      "next",
      [],
      "unknown",
    );
    for (const tax of DATA_LAYER_TAX) expect(taxonomies(findings)).not.toContain(tax);
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
    const findings = detectAppRouterFindings(webFiles, "other", [{ rel: "apps/web", framework: "vite" }]);

    expect(taxonomies(findings)).not.toContain(SSR_API);
    expect(taxonomies(findings)).toContain(NON_SSR_NOTE);
    expect(findings.find((f) => f.taxonomy === NON_SSR_NOTE)?.location).toBe("apps/web");
  });

  it("keeps M9 active on a Next workspace in the same monorepo while the Vite workspace is N/A", () => {
    const webFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/web"); // Vite
    const apiFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/api"); // Next
    const findings = detectAppRouterFindings([...webFiles, ...apiFiles], "other", [{ rel: "apps/web", framework: "vite" }]);

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
    const findings = detectAppRouterFindings(apiFiles, "other", [{ rel: "apps/web", framework: "vite" }]);
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
    const findings = detectAppRouterFindings(webFiles, "other", [{ rel: "apps/web", framework: "vite" }]);
    const boundary = findings.filter((f) => f.taxonomy === SPA_BOUNDARY);
    expect(boundary).toHaveLength(1);
    expect(boundary[0]?.location).toBe("apps/web/main.tsx:5");
  });
});

// #872: a recognised non-Next framework (Astro / SvelteKit / Nuxt) has no adapter yet, so the
// Next-shaped pass is suppressed and disclosed as not-assessed rather than run over a false premise.
// Remix / React Router 7 / TanStack Start now route to their own adapters (#916/#917/#918) below.
const UNSUPPORTED_FW_NOTE = "M9 — Not assessed (framework unsupported)";

describe("recognised-but-unsupported framework gate (#872)", () => {
  it("analyses a Remix target on its adapter — the SSR check runs (framework-agnostic detector)", () => {
    // Remix routes to the boundary-model adapter now: the framework-agnostic SSR-misuse detector
    // fires, and there is no blanket unsupported-framework note.
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-browser-api/positive"), "remix");
    expect(taxonomies(findings)).toContain(SSR_API);
    expect(taxonomies(findings)).not.toContain(UNSUPPORTED_FW_NOTE);
  });

  it("does not claim the SPA root-error-boundary check ran on a non-SPA framework", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("spa-error-boundary/positive"), "sveltekit");
    expect(taxonomies(findings)).not.toContain(SPA_BOUNDARY);
    expect(taxonomies(findings)).toContain(UNSUPPORTED_FW_NOTE);
  });

  it("suppresses per workspace in a monorepo while a Next workspace still runs", () => {
    const siteFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/site");
    const apiFiles = prefixPaths(loadFixtureDir("ssr-browser-api/positive"), "apps/api");
    const findings = detectAppRouterFindings([...siteFiles, ...apiFiles], "other", [{ rel: "apps/site", framework: "astro" }]);
    const note = findings.find((f) => f.taxonomy === UNSUPPORTED_FW_NOTE);
    expect(note?.location).toBe("apps/site");
    expect(note?.evidence).toContain("Astro");
    const ssr = findings.filter((f) => f.taxonomy === SSR_API);
    expect(ssr.length).toBeGreaterThan(0);
    expect(ssr.every((f) => f.location.startsWith("apps/api/"))).toBe(true);
  });

  it("still runs the full pass on `other` — an unrecognised shape is not a licence to skip", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-browser-api/positive"), "other");
    expect(taxonomies(findings)).toContain(SSR_API);
    expect(taxonomies(findings)).not.toContain(UNSUPPORTED_FW_NOTE);
  });
});

const LEAK = "M9 — Server→client data leak";
const WATERFALL = "M9 — Data-fetching waterfall";

// #917 — Remix / React Router 7 adapter on the boundary model.
describe("Remix / React Router 7 boundary adapter (#917)", () => {
  for (const framework of ["remix", "react-router"] as const) {
    it(`flags a full DB row returned from a loader (${framework})`, () => {
      const findings = detectAppRouterFindings(loadFixtureDir("remix/leak/positive"), framework);
      const leaks = findings.filter((f) => f.taxonomy === LEAK);
      expect(leaks).toHaveLength(1);
      expect(leaks[0]?.title).toContain("Remix loader");
      expect(leaks[0]?.location).toBe("app/routes/dashboard.tsx:7");
      expect(leaks[0]?.precisionTier).toBe("review");
    });

    it(`stays silent when the loader returns a narrowed projection (${framework})`, () => {
      const findings = detectAppRouterFindings(loadFixtureDir("remix/leak/negative"), framework);
      expect(taxonomies(findings)).not.toContain(LEAK);
    });
  }

  it("flags an action mutating with no auth check, with the framework-true noun", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("remix/action-authz/positive"), "remix");
    const hits = findings.filter((f) => f.taxonomy === "M1 — route action missing authorization check");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("route action");
  });

  it("flags an action reading input into a mutation with no validation", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("remix/action-validation/positive"), "remix");
    expect(taxonomies(findings)).toContain("M9 — route action missing input validation");
  });

  // #964: carbon validates through `@carbon/form`'s `validator(schema).validate(...)` wrapper — a
  // BARE `validator(` call plus `.validate(`, which the old dotted-only regex missed, false-firing
  // High on fully-validated route actions (its OAuth token endpoint). Recognise the idiom.
  it("does not flag a route action validated through the `validator(schema).validate(...)` wrapper", () => {
    const findings = detectAppRouterFindings(
      [
        {
          path: "app/routes/_oauth+/token.tsx",
          text: `import { validator } from "@carbon/form";\nimport { oauthTokenValidator } from "./validators";\nexport async function action({ request }: { request: Request }) {\n  const validation = await validator(oauthTokenValidator).validate(await request.formData());\n  await db.from("oauthToken").insert({ token: validation.data.token });\n  return null;\n}\n`,
        },
      ],
      "react-router",
    );
    expect(taxonomies(findings)).not.toContain("M9 — route action missing input validation");
  });

  it("reuses the framework-agnostic SSR-misuse and waterfall detectors on Remix files", () => {
    expect(taxonomies(detectAppRouterFindings(loadFixtureDir("ssr-browser-api/positive"), "remix"))).toContain(SSR_API);
    expect(taxonomies(detectAppRouterFindings(loadFixtureDir("waterfall/positive"), "remix"))).toContain(WATERFALL);
  });

  it("discloses every non-ported check as a not-assessed row naming the framework", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("remix/leak/positive"), "remix");
    const na = findings.filter((f) => f.confidence === "N/A" && f.taxonomy.includes("not assessed"));
    expect(na.some((f) => f.taxonomy.includes("cache config"))).toBe(true);
    expect(na.some((f) => f.taxonomy.includes("route segment"))).toBe(true);
    expect(na.every((f) => f.taxonomy.includes("Remix"))).toBe(true);
  });
});

// #918 — TanStack Start adapter (createServerFn shape).
describe("TanStack Start boundary adapter (#918)", () => {
  it("flags a full DB row returned from a createServerFn handler", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("tanstack/leak/positive"), "tanstack-start");
    const leaks = findings.filter((f) => f.taxonomy === LEAK);
    expect(leaks).toHaveLength(1);
    expect(leaks[0]?.title).toContain("TanStack server function");
    expect(leaks[0]?.evidence).toContain("getUser");
  });

  it("stays silent on a narrowed createServerFn return", () => {
    expect(taxonomies(detectAppRouterFindings(loadFixtureDir("tanstack/leak/negative"), "tanstack-start"))).not.toContain(LEAK);
  });

  it("flags a server function mutating with no auth check", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("tanstack/action-authz/positive"), "tanstack-start");
    const hits = findings.filter((f) => f.taxonomy === "M1 — server function missing authorization check");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("server function");
  });

  it("counts a chain-level `.validator()` as input validation (no false missing-validation)", () => {
    // action-authz/positive has `.validator(z.object(...))` — validation must NOT fire, only authz.
    const findings = detectAppRouterFindings(loadFixtureDir("tanstack/action-authz/positive"), "tanstack-start");
    expect(taxonomies(findings)).not.toContain("M9 — server function missing input validation");
  });

  it("flags a server function with no validator and no body validation", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("tanstack/action-validation/positive"), "tanstack-start");
    expect(taxonomies(findings)).toContain("M9 — server function missing input validation");
  });

  it("clears the validator-guarded negative", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("tanstack/action-validation/negative"), "tanstack-start");
    expect(taxonomies(findings)).not.toContain("M9 — server function missing input validation");
  });
});
