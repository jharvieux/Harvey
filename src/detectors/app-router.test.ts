import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildImportGraph, collectPathAliases, detectAppRouterFindings, resolveImport, type SourceInput } from "./app-router.js";
import { parse } from "./common.js";

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

// #1434 — the residual #1263 left: this detector kept the raw-text AUTH_PATTERN test, so a
// house-style gate was invisible to it and its evidence asserted "makes no auth/session call at
// all". #1484 split the bundled `owner-id-helper-gate` fixture (logger + comment shapes, one
// `match` key) into its own dir per shape — see M9C-OWNER-GATE-LOGGER-POS/NEG and
// M9C-OWNER-GATE-COMMENT-POS/NEG in calibration/m9-checks.entries.ts.
describe("client-supplied owner id — house-style gate resolution (#1434)", () => {
  it("does not flag a service-role action gated by a resolvable helper that can deny", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("owner-id-helper-gate-logger/negative"));
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID_NOAUTH);
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID);
    // Scope control: the fixture WAS scanned. A dir the loader never read reports the same zero.
    expect(taxonomies(findings)).toContain("M9 — Server Action missing input validation");
  });

  it("still flags a logger that reads the session but cannot deny", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("owner-id-helper-gate-logger/positive"));
    const hits = findings.filter((f) => f.taxonomy === CLIENT_OWNER_ID_NOAUTH);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("updateUserProfile");
  });

  it("still flags the word `auth` in a comment, not a real call", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("owner-id-helper-gate-comment/positive"));
    const hits = findings.filter((f) => f.taxonomy === CLIENT_OWNER_ID_NOAUTH);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("updateUserEmail");
  });

  it("does not flag the comment shape's negative, where the same call is real, not commented out", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("owner-id-helper-gate-comment/negative"));
    expect(taxonomies(findings)).not.toContain(CLIENT_OWNER_ID_NOAUTH);
  });

  it("never claims a helper was read and cleared when none authenticates", () => {
    for (const dir of ["owner-id-helper-gate-logger/positive", "owner-id-helper-gate-comment/positive"]) {
      const findings = detectAppRouterFindings(loadFixtureDir(dir));
      const hits = findings.filter((f) => f.taxonomy === CLIENT_OWNER_ID_NOAUTH);
      for (const f of hits) {
        // The claim #1434 exists to remove. What replaces it names both what was read and its bound.
        expect(f.evidence).not.toContain("makes no auth/session call at all");
        expect(f.evidence).toContain("none in any helper it calls that this pass could resolve");
      }
    }
  });
});

// #1717 — #1502's cross-file SSR caller search followed ONE hop of `export { x } from "./barrel"`,
// and carbon's `handleCommandNavigation` stayed flagged. Both #1717's body and carbon's own baseline
// note diagnosed that as a DEPTH problem; MEASURED, it was not — extending the chase to 3 hops moved
// nothing on any pinned target. The middle barrel is a bare `export * from "./slash-command"`, which
// `collectReExports` skips because it has no export clause, so it was invisible at any depth.
// Both halves ship, and this block gates both plus the bound itself.
describe("SSR cross-file callers through a barrel chain (#1717)", () => {
  const SSR = "M9 — SSR-only API misuse";
  const HELPER = 'export function handleCommandNavigation(event: unknown) {\n  return document.activeElement;\n}\n';
  // The caller is deferred to a useEffect, so it is OFF the render path: resolving it must SPARE the
  // helper. That is what makes each assertion below a statement about resolution — an unresolved
  // chain leaves the finding standing, so "flagged" and "chain not followed" are the same output.
  const CALLER = (specifier: string) =>
    `import { handleCommandNavigation } from "${specifier}";\nimport { useEffect } from "react";\n\nexport function SlashCommand() {\n  useEffect(() => {\n    handleCommandNavigation(null);\n  }, []);\n  return <div />;\n}\n`;
  const ssrRows = (files: SourceInput[]) => detectAppRouterFindings(files).filter((f) => f.taxonomy === SSR);

  it("follows a `export * from` barrel — the shape carbon actually has", () => {
    const files = [
      { path: "lib/slash-command.tsx", text: HELPER },
      { path: "lib/index.ts", text: 'export * from "./slash-command";\n' },
      { path: "app/component.tsx", text: CALLER("../lib/index") },
    ];
    expect(ssrRows(files)).toEqual([]);
  });

  it("follows TWO hops — a named barrel above a star barrel, carbon's exact chain", () => {
    const files = [
      { path: "lib/extensions/slash-command.tsx", text: HELPER },
      { path: "lib/extensions/index.ts", text: 'export * from "./slash-command";\n' },
      { path: "lib/index.ts", text: 'export { handleCommandNavigation } from "./extensions/index";\n' },
      { path: "app/component.tsx", text: CALLER("../lib/index") },
    ];
    expect(ssrRows(files)).toEqual([]);
  });

  it("follows a RENAMING hop, resolving the symbol under the name each barrel exports it as", () => {
    const files = [
      { path: "lib/slash-command.tsx", text: HELPER },
      { path: "lib/inner.ts", text: 'export { handleCommandNavigation as navigate } from "./slash-command";\n' },
      { path: "lib/index.ts", text: 'export { navigate as handleCommandNavigation } from "./inner";\n' },
      { path: "app/component.tsx", text: CALLER("../lib/index") },
    ];
    expect(ssrRows(files)).toEqual([]);
  });

  // THE ADVERSARIAL CONTROL AT THE BOUND, mirroring #1500's GATE_DEPTH one. A chain one hop deeper
  // than BARREL_CHASE_DEPTH must leave the finding STANDING — the bound fails toward reporting, not
  // toward silence. Raising the constant makes this test red, which is the point: the number is
  // asserted, not merely written down.
  it("stops at BARREL_CHASE_DEPTH — a chain one hop deeper stays FLAGGED, not silently spared", () => {
    const files = [
      { path: "lib/slash-command.tsx", text: HELPER },
      { path: "lib/b1.ts", text: 'export * from "./slash-command";\n' },
      { path: "lib/b2.ts", text: 'export * from "./b1";\n' },
      { path: "lib/b3.ts", text: 'export * from "./b2";\n' },
      { path: "lib/b4.ts", text: 'export * from "./b3";\n' },
      { path: "app/component.tsx", text: CALLER("../lib/b4") },
    ];
    const rows = ssrRows(files);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.location).toContain("lib/slash-command.tsx");
    // …and exactly one hop shallower DOES resolve, so the assertion above is about the bound and
    // not about some unrelated reason the chain never worked.
    const withinBound = files.filter((f) => f.path !== "lib/b4.ts").map((f) => (f.path === "app/component.tsx" ? { ...f, text: CALLER("../lib/b3") } : f));
    expect(ssrRows(withinBound)).toEqual([]);
  });

  // A star barrel must not become a wildcard that spares anything: the helper's name has to really
  // be exported by the module the star points at.
  it("does not resolve a name the starred module does not export", () => {
    const files = [
      { path: "lib/slash-command.tsx", text: HELPER },
      { path: "lib/other.ts", text: "export function unrelated() {}\n" },
      { path: "lib/index.ts", text: 'export * from "./other";\n' },
      { path: "app/component.tsx", text: CALLER("../lib/index") },
    ];
    expect(ssrRows(files)).toHaveLength(1);
  });
});

// #1652 — the two policy exclusions in detectClientSuppliedOwnerId used to `continue` in silence,
// so a target where every client-owner-id site was set aside reported zero rows of the class and
// nothing said a class had been set aside. Both exclusions now emit into one counted N/A row, the
// same shape #1441 gave the waterfall check.
const OWNER_ID_SCOPE = "M1 — Client-supplied owner id — scope";
describe("the two policy exclusions are counted, not silent (#1652)", () => {
  // Exclusion 2: an OWNERSHIP_COLUMN site on the plain RLS client with no auth call. Written inline
  // rather than reusing `client-owner-id/negative-rls-bareid`, which #1652's body names as this
  // exclusion's instance and WHICH DOES NOT REACH IT (MEASURED: that fixture's column is `id`, and
  // findClientOwnerSite only admits a bare `id` on a service-rooted chain, so no site is ever found
  // and the `continue` at the exclusion never runs). The issue's claim is corrected on the issue.
  const rlsFindings = detectAppRouterFindings([
    {
      path: "app/actions.ts",
      text: `"use server";\nimport { createClient } from "@/lib/supabase";\n\nexport async function updateOrganisationLogo(input: { user_id: string; logo: string }) {\n  const supabase = createClient();\n  await supabase.from("profiles").update({ logo: input.logo }).eq("user_id", input.user_id);\n}\n`,
    },
  ]);
  // Exclusion 1: a resolvable house-style gate that CAN deny, so auth is called and nothing bound.
  const gateFindings = detectAppRouterFindings(loadFixtureDir("owner-id-helper-gate-logger/negative"));

  it("emits the scope row for the RLS-client exclusion, with its population", () => {
    const rows = rlsFindings.filter((f) => f.taxonomy === OWNER_ID_SCOPE);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.confidence).toBe("N/A");
    expect(rows[0]?.title).toContain("1 of 1 site excluded by policy");
    expect(rows[0]?.evidence).toContain("row-level security still gates the write");
    // The exclusion's own premise: the class stayed silent and the generic finding owns the defect.
    expect(taxonomies(rlsFindings)).not.toContain(CLIENT_OWNER_ID_NOAUTH);
    expect(taxonomies(rlsFindings)).toContain(MISSING_AUTH);
  });

  it("emits it for the auth-called-but-nothing-bound exclusion too, naming that class instead", () => {
    const rows = gateFindings.filter((f) => f.taxonomy === OWNER_ID_SCOPE);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.evidence).toContain("binds no session value from it");
    expect(rows[0]?.evidence).not.toContain("row-level security still gates the write");
  });

  // The failing direction, and the one that matters most: this row must NOT appear on a target where
  // nothing was set aside, or it stops being a disclosure and becomes a status line printed on every
  // report. Both fixtures below produce a real finding of the class, so the check ran and had a
  // population — they are not zero-by-not-scanning.
  it("is ABSENT when the check set nothing aside", () => {
    for (const dir of ["client-owner-id/positive", "client-owner-id/positive-svc-bareid"]) {
      const findings = detectAppRouterFindings(loadFixtureDir(dir));
      expect(taxonomies(findings)).not.toContain(OWNER_ID_SCOPE);
      expect(findings.some((f) => f.taxonomy === CLIENT_OWNER_ID || f.taxonomy === CLIENT_OWNER_ID_NOAUTH)).toBe(true);
    }
  });

  // Counting the exclusions required moving both policy tests to AFTER findClientOwnerSite, so that
  // the denominator is "sites that really had a client-supplied owner id" rather than "actions".
  // That move must change no finding: this pins the emitted set across all nine fixtures, so a
  // reordering that quietly widened or narrowed the class fails here rather than in a baseline.
  it("changes no finding — every fixture's non-scope taxonomy set is what it was", () => {
    const emitted = (dir: string) =>
      [...new Set(detectAppRouterFindings(loadFixtureDir(`client-owner-id/${dir}`)).map((f) => f.taxonomy))].filter((t) => t !== OWNER_ID_SCOPE).sort();
    const VALIDATION = "M9 — Server Action missing input validation";
    expect(emitted("positive")).toEqual([CLIENT_OWNER_ID]);
    expect(emitted("positive-delete")).toEqual([CLIENT_OWNER_ID]);
    expect(emitted("positive-svc-bareid")).toEqual([CLIENT_OWNER_ID_NOAUTH, VALIDATION].sort());
    expect(emitted("positive-svc-insert")).toEqual([CLIENT_OWNER_ID_NOAUTH, VALIDATION].sort());
    expect(emitted("negative-rls-bareid")).toEqual([MISSING_AUTH, VALIDATION].sort());
    expect(emitted("negative-session-derived")).toEqual([]);
    expect(emitted("negative-ownership-compared")).toEqual([]);
    expect(emitted("negative-svc-insert-session")).toEqual([VALIDATION]);
    expect(emitted("negative-svc-compared-dbrow")).toEqual([MISSING_AUTH, VALIDATION].sort());
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

  // #1484 split the bundled `cache-bleed` fixture (three shapes, one match key) into one dir per
  // shape, each with its own corpus pair — see calibration/m9-checks.entries.ts.
  it("flags per-user data cached under a global unstable_cache key", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-bleed-unstable-cache/positive"));
    const bleeds = findings.filter((f) => f.taxonomy === BLEED);
    expect(bleeds).toHaveLength(1);
    expect(bleeds[0]).toMatchObject({ severity: "High", category: "Security", location: "app/orders/page.tsx:7" });
  });

  it("flags a session read inside a `use cache` scope", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-bleed-use-cache/positive"));
    const bleeds = findings.filter((f) => f.taxonomy === BLEED);
    expect(bleeds).toHaveLength(1);
    expect(bleeds[0]).toMatchObject({ severity: "High", category: "Security", location: "app/dashboard/page.tsx:6" });
  });

  it("flags a public Cache-Control on an authenticated response", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("cache-bleed-cache-control/positive"));
    const bleeds = findings.filter((f) => f.taxonomy === BLEED);
    expect(bleeds).toHaveLength(1);
    expect(bleeds[0]).toMatchObject({ severity: "High", category: "Security", location: "app/api/invoices/route.ts" });
  });

  it("stays quiet when the identity is in the cache key, arrives as a `use cache` argument, or the response is private", () => {
    for (const dir of ["cache-bleed-unstable-cache/negative", "cache-bleed-use-cache/negative", "cache-bleed-cache-control/negative"]) {
      expect(taxonomies(detectAppRouterFindings(loadFixtureDir(dir)))).not.toContain(BLEED);
    }
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

  // #1484: the bundled `waterfall-escape` fixture carried BOTH shapes in one dir, and a `match` key
  // is satisfied by any one finding — so its corpus entry would stay green with half the fix
  // reverted. Split into `waterfall-escape-switch` / `waterfall-escape-loop`, each with its own
  // corpus pair, so a regression in either shape fails the ROW that names it rather than hiding
  // behind the other shape's finding.
  it("the switch-break fixture still fires — the escape rule narrows the switch case, not the pair", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall-escape-switch/positive"));
    const hits = findings.filter((f) => f.taxonomy === WATERFALL_TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("projects");
  });

  it("the inner-loop-break fixture still fires — the escape rule narrows the loop, not the pair", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall-escape-loop/positive"));
    const hits = findings.filter((f) => f.taxonomy === WATERFALL_TAX);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).toContain("invoices");
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

  // #1484: the abort relaxation changes which ERROR surfaces, not just control flow — sequentially
  // the guard's own throw always wins; under Promise.all a rejection from the second query can
  // surface instead, which matters on a data layer that REJECTS (Prisma, a raw driver) rather than
  // returning an error object (Supabase's `.error`). The finding must say so, and only when this
  // relaxation is actually why the pair fired — not on an ordinary independent pair with no guard.
  it("names the error-precedence change in the finding's own text when the abort relaxation is why the pair fired", () => {
    const findings = detectAppRouterFindings([{ path: PAGE, text: READ_THEN_READ }]);
    const wf = findings.find((f) => f.taxonomy === WATERFALL_TAX);
    expect(wf?.evidence).toContain("error-only guard between them was excused");
    expect(wf?.evidence).toContain("Prisma");
    expect(wf?.fix).toContain("rejecting data layer");
  });

  it("does not add the error-precedence caveat to an ordinary independent pair with no guard at all", () => {
    const text = `export default async function Page() {\n  const { data: teams } = await supabase.from("teams").select("id");\n  const { data: projects } = await supabase.from("projects").select("id");\n  return { teams, projects };\n}\n`;
    const findings = detectAppRouterFindings([{ path: PAGE, text }]);
    const wf = findings.find((f) => f.taxonomy === WATERFALL_TAX);
    expect(wf?.evidence).not.toContain("error-only guard between them was excused");
    expect(wf?.fix).not.toContain("rejecting data layer");
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

  // #1484: the bundled `action-gate-strength` fixture carried BOTH shapes in one dir, so its
  // corpus entry's `match` key would stay green with half the fix reverted. Split into
  // `action-gate-strength-logger` / `action-gate-strength-discarded`, each with its own pair.
  it("does not accept a LOGGER as a gate, however much its body reads the session", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("action-gate-strength-logger/positive"));
    const hits = findings.filter((f) => f.taxonomy === AUTHZ);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("renameLogged");
  });

  it("does not accept a boolean gate whose result is discarded", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("action-gate-strength-discarded/positive"));
    const hits = findings.filter((f) => f.taxonomy === AUTHZ);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.title).toContain("renameUnchecked");
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
    expect(taxonomies(detectAppRouterFindings(loadFixtureDir("action-gate-strength-logger/negative")))).not.toContain(AUTHZ);
    expect(taxonomies(detectAppRouterFindings(loadFixtureDir("action-gate-strength-discarded/negative")))).not.toContain(AUTHZ);
  });

  it("still resolves the named-import gate #1263 shipped — the namespace path is an addition, not a swap", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-helper-gate/negative"));
    expect(taxonomies(findings)).not.toContain(AUTHZ);
  });

  // #1500: the dynamic-import-wrapper resolution is narrow ON PURPOSE — only a THIN PASSTHROUGH
  // (`return [await] import("literal")`, nothing else) counts. A wrapper that does anything else
  // (extra logic before/after the import) is a shape this pass does not evaluate, so it must leave
  // the finding standing rather than guessing — the same suppression-only bound every other
  // resolution step in this file keeps.
  it("does not resolve a dynamic-import wrapper that does more than passthrough — the finding stays standing", () => {
    const action = `"use server";\nimport { requireAdmin } from "../lib/roles";\nimport { supabase } from "../lib/db";\nexport async function rename(id: string, name: string) {\n  await requireAdmin();\n  await supabase.from("projects").update({ name }).eq("id", id);\n}\n`;
    // The real gate is one hop further, in `getAuthenticatedUser` (matches AUTH_PATTERN AND
    // throws) — reachable only through `loadAuthServer`, whose body does more than passthrough
    // the dynamic import (`console.log` first), so this pass must not resolve it.
    const roles = `async function loadAuthServer() {\n  console.log("loading auth server");\n  return import("./auth-helpers");\n}\nexport async function requireAdmin() {\n  const { getAuthenticatedUser } = await loadAuthServer();\n  await getAuthenticatedUser();\n}\n`;
    const helpers = `export async function getAuthenticatedUser() {\n  const user = await getCurrentUser();\n  if (!user) throw new Error("unauthenticated");\n  return user;\n}\n`;
    const findings = detectAppRouterFindings([
      { path: "app/actions.ts", text: action },
      { path: "lib/roles.ts", text: roles },
      { path: "lib/auth-helpers.ts", text: helpers },
    ]);
    // The real gate lives behind the impure wrapper — unreached, so the action still reads as
    // missing authorization even though `getAuthenticatedUser` genuinely denies unauthorized callers.
    expect(taxonomies(findings)).toContain(AUTHZ);
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

describe("gate reached through a dynamic import (#1462)", () => {
  const AUTHZ = "M1 — Server Action missing authorization check";

  // #1484 criterion 3, second pass: these four shapes used to live in ONE fixture dir behind ONE
  // corpus entry that passed on any one of them. They are four dirs and four corpus rows now, and
  // this suite asserts each on its own fixture rather than counting four evidences in one.
  const SHAPES = [
    { shape: "named", why: "a destructured dynamic import that resolves, to a helper that checks nothing" },
    { shape: "namespace", why: "the namespace form of the same non-gate module" },
    { shape: "computed", why: "a COMPUTED specifier, so the module goes unidentified" },
    { shape: "package", why: "a specifier naming a package outside the loaded source set" },
  ];

  for (const { shape, why } of SHAPES) {
    it(`clears the gated action reached through a ${shape} dynamic import`, () => {
      // The shape MEASURED on TanStack/tanstack.com: `requireAdmin` binds its real check with a
      // dynamic import, so #1263's resolver saw a callee that matched nothing and stopped.
      const findings = detectAppRouterFindings(loadFixtureDir(`server-action-dynamic-gate-${shape}/negative`));
      expect(taxonomies(findings)).not.toContain(AUTHZ);
    });

    it(`leaves the ${shape} shape flagged — ${why}`, () => {
      // Widening resolution must not turn "awaits something it imported dynamically" into "is
      // gated", and a specifier this pass does not evaluate must leave the finding standing.
      const findings = detectAppRouterFindings(loadFixtureDir(`server-action-dynamic-gate-${shape}/positive`));
      const flagged = findings.filter((f) => f.taxonomy === AUTHZ).map((f) => f.evidence);
      expect(flagged).toHaveLength(1);
      expect(flagged[0]).toContain("`renameOrganisation`");
    });
  }
});

describe("browser global in a module-level helper (#1460)", () => {
  const SSR = "M9 — SSR-only API misuse";

  it("clears a helper whose only in-file call site is inside a useEffect", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-module-helper/negative"));
    expect(taxonomies(findings)).not.toContain(SSR);
  });

  it("still flags the same helper when the component's render body calls it", () => {
    // The recall half: the naive "a lowercase module-level function with no JSX is off the render
    // path" rule reads this file and the negative identically — only the call sites separate them.
    const findings = detectAppRouterFindings(loadFixtureDir("ssr-module-helper/positive"));
    const ssr = findings.filter((f) => f.taxonomy === SSR);
    expect(ssr).toHaveLength(1);
    expect(ssr[0]?.evidence).toContain("currentOrigin");
  });
});

describe("waterfall guard exiting inside a helper (#1461)", () => {
  const WATERFALL = "M9 — Data-fetching waterfall";

  it("clears the pair when the intervening statement's callee can deny, over a write", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall-helper-exit/negative"));
    expect(taxonomies(findings)).not.toContain(WATERFALL);
  });

  it("still flags the pair when the callee only returns — a return leaves the helper, not the caller", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("waterfall-helper-exit/positive"));
    expect(taxonomies(findings)).toContain(WATERFALL);
  });
});

describe("import resolution across a monorepo's workspaces (#1461)", () => {
  it("resolves an aliased import against the tsconfig of the workspace that declares it", () => {
    // Before #1461 collectPathAliases stopped at the shallowest config with `paths` and applied
    // only its aliases repo-wide, so on a monorepo every other workspace's `~/…` specifier
    // resolved to nothing and every cross-file pass went quietly blind there (MEASURED on
    // crbnos/carbon: `docs/tsconfig.json` won, and four workspaces' `~/*` never resolved).
    const findings = detectAppRouterFindings([
      { path: "docs/tsconfig.json", text: JSON.stringify({ compilerOptions: { paths: { "@/*": ["./*"] } } }) },
      { path: "apps/erp/tsconfig.json", text: JSON.stringify({ compilerOptions: { paths: { "~/*": ["./app/*"] } } }) },
      {
        path: "apps/erp/app/actions.ts",
        text: `"use server";\nimport { z } from "zod";\nimport { supabase } from "~/lib/db";\nimport { ensureMember } from "~/lib/gates";\nconst S = z.object({ id: z.string() });\nexport async function rename(input: unknown) {\n  const { id } = S.parse(input);\n  await ensureMember(id);\n  await supabase.from("orgs").update({ name: "x" }).eq("id", id);\n}\n`,
      },
      {
        path: "apps/erp/app/lib/gates.ts",
        text: `import { supabase } from "./db";\nexport async function ensureMember(id: string) {\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) throw new Error("unauthenticated");\n  return user;\n}\n`,
      },
      { path: "apps/erp/app/lib/db.ts", text: `export const supabase = {} as any;\n` },
    ]);
    expect(taxonomies(findings)).not.toContain("M1 — Server Action missing authorization check");
  });
});

describe("client-reachability of a server-exclusive module (#1461)", () => {
  const GUARD = "M9 — Missing server-only guard";
  const secretModule = { path: "lib/secrets.ts", text: `export const key = process.env.STRIPE_SECRET_KEY;\n` };

  it("flags the module when an ordinary client-imported module reaches it", () => {
    // The control: without a boundary in the chain the finding must still fire, so neither rule
    // below can be satisfied by suppressing the whole class.
    const findings = detectAppRouterFindings([
      { path: "app/page.tsx", text: `"use client";\nimport { helper } from "../lib/helper";\nexport default function P() { return <p>{helper()}</p>; }\n` },
      { path: "lib/helper.ts", text: `import { key } from "./secrets";\nexport function helper() { return key; }\n` },
      secretModule,
    ]);
    expect(taxonomies(findings)).toContain(GUARD);
  });

  it("does not count a type-only import as an edge into the client bundle", () => {
    // `import type { AppRouter } from …` in a 'use client' tRPC provider is erased at compile time.
    // Counting it made rallly's whole server router tree read as client-reachable.
    const findings = detectAppRouterFindings([
      { path: "app/page.tsx", text: `"use client";\nimport type { Helper } from "../lib/helper";\nexport default function P(_: Helper) { return <p>hi</p>; }\n` },
      { path: "lib/helper.ts", text: `import { key } from "./secrets";\nexport type Helper = string;\nexport function helper() { return key; }\n` },
      secretModule,
    ]);
    expect(taxonomies(findings)).not.toContain(GUARD);
  });

  it("stops the walk at a 'use server' module — the client gets an RPC reference, not the body", () => {
    const findings = detectAppRouterFindings([
      { path: "app/page.tsx", text: `"use client";\nimport { save } from "../lib/actions";\nexport default function P() { return <button onClick={() => save()}>go</button>; }\n` },
      { path: "lib/actions.ts", text: `"use server";\nimport { key } from "./secrets";\nexport async function save() { return key; }\n` },
      secretModule,
    ]);
    expect(taxonomies(findings)).not.toContain(GUARD);
  });

  it("stops the walk at an `import \"server-only\"` poison pill", () => {
    const findings = detectAppRouterFindings([
      { path: "app/page.tsx", text: `"use client";\nimport { helper } from "../lib/helper";\nexport default function P() { return <p>{helper()}</p>; }\n` },
      { path: "lib/helper.ts", text: `import "server-only";\nimport { key } from "./secrets";\nexport function helper() { return key; }\n` },
      secretModule,
    ]);
    expect(taxonomies(findings)).not.toContain(GUARD);
  });
});

// #1353 — the import graph used to stop at the package boundary. #1344 gated M7's generic
// sync-I/O tier on import-reachability from a request entry point, which silenced three MEASURED
// true positives in shared monorepo packages (rallly packages/utils pbkdf2Sync, two documenso rows)
// purely because `@rallly/utils` resolved to nothing. Every consumer of resolveImport had the same
// blind spot in the MISSING-findings direction: detectMissingServerOnly's client-reachability
// check, service-role-literal.ts, and M9's whole graph.
describe("import resolution across a workspace (#1353)", () => {
  const files = loadFixtureDir("perf/workspace-reachability");
  const allPaths = new Set(files.map((f) => f.path));
  const aliases = collectPathAliases(files);
  const from = "apps/web/app/api/reset/route.ts";

  it("resolves a workspace package specifier to the member's entry module", () => {
    // `main: "./src/index.ts"` and `exports: { ".": … }` are both in the fixture — neither is a
    // path the resolver could have guessed from the specifier alone.
    expect(resolveImport(from, "@acme/crypto", allPaths, aliases)).toBe("packages/crypto/src/index.ts");
    expect(resolveImport(from, "@acme/utils", allPaths, aliases)).toBe("packages/utils/src/index.ts");
  });

  it("resolves a subpath under a workspace package specifier", () => {
    expect(resolveImport(from, "@acme/utils/src/slugify", allPaths, aliases)).toBe("packages/utils/src/slugify.ts");
  });

  // #1501: #1353 read only `exports` keys carrying a `*`, because that is what rallly declares. An
  // exports map of LITERAL keys is at least as common (crbnos/carbon's `packages/auth` has eleven)
  // and resolved to nothing, which cost 107 false High `route action missing authorization check`
  // rows on that target. Both halves are asserted: the literal key must resolve THROUGH the exports
  // map (its target is not derivable from the specifier — `./auth.server` lives at
  // `src/services/auth.server.ts`), and a key the map does not declare must stay unresolved.
  it("resolves an EXACT, non-wildcard exports subpath through the exports map", () => {
    const tree = [
      {
        path: "packages/auth/package.json",
        text: JSON.stringify({
          name: "@acme/auth",
          main: "./src/index.ts",
          exports: { ".": "./src/index.ts", "./auth.server": "./src/services/auth.server.ts" },
        }),
      },
      { path: "packages/auth/src/index.ts", text: "export const a = 1;" },
      { path: "packages/auth/src/services/auth.server.ts", text: "export function requirePermissions() {}" },
      { path: "apps/web/app/routes/x.tsx", text: "" },
    ];
    const paths = new Set(tree.map((f) => f.path));
    const treeAliases = collectPathAliases(tree);
    const importer = "apps/web/app/routes/x.tsx";
    expect(resolveImport(importer, "@acme/auth/auth.server", paths, treeAliases)).toBe("packages/auth/src/services/auth.server.ts");
    expect(resolveImport(importer, "@acme/auth", paths, treeAliases)).toBe("packages/auth/src/index.ts");
    // Not declared in `exports` and not present under the package dir — the fallback must not invent it.
    expect(resolveImport(importer, "@acme/auth/session.server", paths, treeAliases)).toBeUndefined();
  });

  it("does not resolve a third-party package that merely shares a member's prefix", () => {
    expect(resolveImport(from, "@acme/utils-external", allPaths, aliases)).toBeUndefined();
    expect(resolveImport(from, "react", allPaths, aliases)).toBeUndefined();
  });

  it("reads the tsconfig nearest the importing file, not the shallowest one with paths", () => {
    // Root tsconfig maps @/* -> shared/*; apps/web's own maps @/* -> apps/web/*. The root's is
    // shallower, so before #1353 it won and every `@/…` inside apps/web resolved to nothing.
    expect(resolveImport(from, "@/lib/session", allPaths, aliases)).toBe("apps/web/lib/session.ts");
  });

  // Three independent fixes landed in collectPathAliases on 2026-07-28, from three separate PRs,
  // and this pins that they COMPOSE rather than one quietly undoing another: #1479's variant
  // filename, #1461's per-config scoping, and #1353's workspace-package resolution — all on one
  // Nx-shaped tree with NO plain root tsconfig.json, the ghostfolio shape that disconnected the
  // whole graph. Each assertion below is falsifiable by reverting exactly one of the three.
  it("reads tsconfig.base.json, scopes a nested config, and still resolves a workspace package", () => {
    const nx = [
      { path: "tsconfig.base.json", text: JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@myorg/*": ["./libs/*"] } } }) },
      { path: "apps/api/tsconfig.json", text: JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["./src/*"] } } }) },
      { path: "libs/shared/package.json", text: JSON.stringify({ name: "@myorg/shared", main: "./src/index.ts" }) },
      { path: "libs/shared/src/index.ts", text: "export const x = 1;" },
      // No package.json — reachable ONLY through tsconfig.base.json's paths map, so the assertion
      // below isolates the variant-filename fix from the workspace resolver's work.
      { path: "libs/util/index.ts", text: "export const u = 1;" },
      { path: "apps/api/src/handler.ts", text: "export const h = 1;" },
      { path: "apps/api/src/main.ts", text: "" },
    ];
    const paths = new Set(nx.map((f) => f.path));
    const nxAliases = collectPathAliases(nx);
    const importer = "apps/api/src/main.ts";
    // #1479: the paths map lives only in tsconfig.base.json. libs/util carries no manifest, so a
    // narrowed filename regex leaves it unresolvable.
    expect(resolveImport(importer, "@myorg/util", paths, nxAliases)).toBe("libs/util/index.ts");
    // #1353 workspace resolution, on the same tree.
    expect(resolveImport(importer, "@myorg/shared", paths, nxAliases)).toBe("libs/shared/src/index.ts");
    // #1461 scoping: apps/api's own `@/*` applies to apps/api files, and would resolve to nothing
    // if the root's base config had won and stopped the loop.
    expect(resolveImport(importer, "@/handler", paths, nxAliases)).toBe("apps/api/src/handler.ts");
  });

  it("puts the shared package in the route's import closure", () => {
    const graph = buildImportGraph(new Map(files.filter((f) => /\.tsx?$/.test(f.path)).map((f) => [f.path, parse(f.path, f.text)])), allPaths, aliases);
    expect(graph.get(from)).toContain("packages/crypto/src/index.ts");
  });
});

// #1659 — the ESM-TS convention writes `from "./helpers.js"` for a sibling `helpers.ts`, and
// candidatePaths appended extensions VERBATIM (`./helpers.js.ts`, `./helpers.js.tsx`, …), so the
// edge silently vanished. MEASURED over the 17 pinned corpus commits before the fix, in the scope
// corpus-drift scans: 84 of 166 `.js`-suffixed specifiers resolved to nothing and resolve now, all
// on carbon, zero on the other 16 (4,780 without stripping `vendoredSubtrees` — see the comment on
// resolveImport). Exercised through `resolveImport` DIRECTLY — the fallback used to live at one call
// site in src/detectors/slop.ts, so a test that reached it only through slop proved nothing about
// the shared resolver every other consumer uses.
describe("resolveImport: ESM-TS `./x.js` specifiers (#1659)", () => {
  const tree = [
    { path: "tsconfig.json", text: JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@/*": ["./src/*"] } } }) },
    { path: "src/helpers.ts", text: "export function isAtLeastAsNew() {}" },
    { path: "src/mod.mts", text: "export const m = 1;" },
    { path: "src/lib/index.ts", text: "export const l = 1;" },
    // A REAL committed .js next to a .ts of the same stem — the case the fallback must not steal.
    { path: "src/twin.js", text: "export const fromJs = 1;" },
    { path: "src/twin.ts", text: "export const fromTs = 1;" },
    { path: "src/consumer.ts", text: "" },
    { path: "src/aliased.ts", text: "" },
  ];
  const paths = new Set(tree.map((f) => f.path));
  const aliases = collectPathAliases(tree);
  const from = "src/consumer.ts";

  it("resolves `./helpers.js` to the sibling helpers.ts", () => {
    expect(resolveImport(from, "./helpers.js", paths, aliases)).toBe("src/helpers.ts");
  });

  it("resolves the .mjs/.cjs members of the family, and a directory index behind one", () => {
    expect(resolveImport(from, "./mod.mjs", paths, aliases)).toBe("src/mod.mts");
    expect(resolveImport(from, "./lib/index.js", paths, aliases)).toBe("src/lib/index.ts");
  });

  it("applies to an ALIASED specifier too, not only a relative one", () => {
    expect(resolveImport("src/aliased.ts", "@/helpers.js", paths, aliases)).toBe("src/helpers.ts");
  });

  // The failing direction of the fallback's own precedence: it is a FALLBACK, so a real committed
  // `twin.js` still wins over `twin.ts`. Deleting the `verbatim !== undefined` short-circuit — the
  // obvious "simplification" — turns this red while every assertion above stays green.
  it("does NOT re-point a specifier whose literal target exists", () => {
    expect(resolveImport(from, "./twin.js", paths, aliases)).toBe("src/twin.js");
  });

  it("does not invent a target when neither the literal nor the stripped form exists", () => {
    expect(resolveImport(from, "./absent.js", paths, aliases)).toBeUndefined();
    expect(resolveImport(from, "@/absent.js", paths, aliases)).toBeUndefined();
  });

  it("puts the stripped edge in the import graph M9 and #1344 read", () => {
    const withImport = tree.map((f) => (f.path === "src/consumer.ts" ? { ...f, text: 'import { isAtLeastAsNew } from "./helpers.js";\n' } : f));
    const graph = buildImportGraph(new Map(withImport.filter((f) => /\.[cm]?tsx?$/.test(f.path)).map((f) => [f.path, parse(f.path, f.text)])), paths, aliases);
    expect(graph.get(from)).toEqual(["src/helpers.ts"]);
  });
});

// #1680 — a file-level `"use server"` marks that module's EXPORTED functions as RPC endpoints and
// nothing else. All five of inbox-zero's `M1-boundary` rows (@2b78f2b3) were non-exported helpers
// inside such a module, each called by an exported action whose middleware had already authorised
// the caller. A helper the client has no route to is not "a public POST endpoint anyone can trigger".
describe("Server Actions: only an EXPORTED function in a 'use server' module is an endpoint (#1680)", () => {
  const AUTHZ = "M1 — Server Action missing authorization check";
  const useServer = (body: string) => [{ path: "app/actions.ts", text: `"use server";\n\n${body}` }];

  it("does not flag a non-exported helper in a 'use server' module", () => {
    const findings = detectAppRouterFindings(
      useServer(
        `async function deleteCategoryHelper(id: string, emailAccountId: string) {\n  await db.category.delete({ where: { id, emailAccountId } });\n}\n\nexport async function deleteCategoryAction(id: string) {\n  const session = await auth();\n  if (!session) throw new Error("unauthorized");\n  await deleteCategoryHelper(id, session.emailAccountId);\n}\n`,
      ),
    );
    expect(taxonomies(findings)).not.toContain(AUTHZ);
  });

  it("does not flag a non-exported module-level arrow in a 'use server' module", () => {
    const findings = detectAppRouterFindings(useServer(`const purge = async (id: string) => {\n  await db.category.delete({ where: { id } });\n};\n`));
    expect(taxonomies(findings)).not.toContain(AUTHZ);
  });

  // The failing direction: the narrowing must not turn into a blanket silence. Each of the three
  // export spellings is an endpoint and must still fire.
  it("still flags an unguarded `export async function`", () => {
    const findings = detectAppRouterFindings(useServer(`export async function purge(id: string) {\n  await db.category.delete({ where: { id } });\n}\n`));
    expect(taxonomies(findings)).toContain(AUTHZ);
  });

  it("still flags an unguarded `export const` arrow", () => {
    const findings = detectAppRouterFindings(useServer(`export const purge = async (id: string) => {\n  await db.category.delete({ where: { id } });\n};\n`));
    expect(taxonomies(findings)).toContain(AUTHZ);
  });

  it("still flags a function exported by a separate `export { … }` statement", () => {
    const findings = detectAppRouterFindings(useServer(`async function purge(id: string) {\n  await db.category.delete({ where: { id } });\n}\n\nexport { purge };\n`));
    expect(taxonomies(findings)).toContain(AUTHZ);
  });

  // The INLINE directive keeps its old meaning: such an action is commonly passed to a Client
  // Component as a prop rather than exported, so export says nothing about its reachability.
  it("still flags an inline 'use server' action that is never exported", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/page.tsx",
        text: `export default function Page() {\n  async function purge(id: string) {\n    "use server";\n    await db.category.delete({ where: { id } });\n  }\n  return <form action={purge} />;\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).toContain(AUTHZ);
  });
});

// #1681 — MUTATION_PATTERN is name-only, so any receiver with a `.delete()` satisfied it. carbon's
// `apps/mes/app/routes/x+/proxy.$.tsx` has no database write at all and was reported as an
// unguarded one because `headers.delete("host")` read as a data mutation.
describe("route actions: a built-in collection's `.delete()` is not a data mutation (#1681)", () => {
  const AUTHZ = "M1 — route action missing authorization check";
  const route = (text: string) => detectAppRouterFindings([{ path: "app/routes/proxy.tsx", text }], "remix");

  it("does not flag a pure proxy action whose only `.delete()` is on a locally-built Headers", () => {
    const findings = route(
      `export async function action({ request, params }: { request: Request; params: Record<string, string> }) {\n  const headers = new Headers(request.headers);\n  headers.delete("host");\n  headers.delete("origin");\n  return fetch(\`https://erp.example/\${params["*"]}\`, { method: request.method, body: request.body, headers });\n}\n`,
    );
    expect(taxonomies(findings)).not.toContain(AUTHZ);
  });

  it("does not flag a `.delete()` on a URLSearchParams reached through a property", () => {
    const findings = route(
      `export async function action({ request }: { request: Request }) {\n  const url = new URL(request.url);\n  url.searchParams.delete("token");\n  return fetch(url);\n}\n`,
    );
    expect(taxonomies(findings)).not.toContain(AUTHZ);
  });

  // Modelled on flori-web's `src/lib/logger.ts`, which keeps its dedup `new Map()` at MODULE scope
  // and mutates it from inside `isDuplicate`. NOT a reproduction of that exact row: the real
  // `isDuplicate` is not exported, so #1680's export requirement already clears it regardless of
  // this scope — this fixture exports it so the module-wide-vs-body-only distinction has something
  // to exercise. See the population note on `onlyBuiltinCollectionMutations`.
  it("does not flag a `.delete()` on a module-level Map used as an in-memory dedup cache", () => {
    const findings = detectAppRouterFindings([
      {
        path: "app/actions.ts",
        text: `"use server";\n\nconst recentErrors = new Map<string, number>();\n\nexport async function isDuplicate(key: string) {\n  const now = Date.now();\n  for (const [k, v] of recentErrors) {\n    if (now - v > 1000) recentErrors.delete(k);\n  }\n  recentErrors.set(key, now);\n  return false;\n}\n`,
      },
    ]);
    expect(taxonomies(findings)).not.toContain("M1 — Server Action missing authorization check");
  });

  // The failing direction, and the reason the exclusion is per-CALL rather than per-file: an action
  // that scrubs headers AND writes to the database is still an unguarded write.
  it("still flags an action that scrubs headers and then mutates the database", () => {
    const findings = route(
      `import { db } from "../db";\nexport async function action({ request }: { request: Request }) {\n  const form = await request.formData();\n  const headers = new Headers(request.headers);\n  headers.delete("host");\n  await db.from("notes").delete().eq("id", form.get("id"));\n  return new Response("ok");\n}\n`,
    );
    expect(taxonomies(findings)).toContain(AUTHZ);
  });

  it("still flags a plain unguarded delete with no built-in collection anywhere", () => {
    const findings = route(
      `import { db } from "../db";\nexport async function action({ request }: { request: Request }) {\n  const form = await request.formData();\n  await db.from("notes").delete().eq("id", form.get("id"));\n  return new Response("ok");\n}\n`,
    );
    expect(taxonomies(findings)).toContain(AUTHZ);
  });
});
