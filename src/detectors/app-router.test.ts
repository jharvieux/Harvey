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
});

describe("missing server-only guard", () => {
  it("flags a module reading a service-role/secret env var with no 'server-only' import", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("missing-server-only/positive"));
    const hits = findings.filter((f) => f.taxonomy === "M9 — Missing server-only guard");

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security", location: "lib/admin-client.ts:1" });
  });

  it("does not flag a module once it imports 'server-only', a route handler touching the same secret, or a module with no secret access", () => {
    // negative/ covers three distinct non-findings: the guard present, the
    // route-handler exemption (server-exclusive by Next.js routing convention),
    // and a module that never touches a secret at all.
    const findings = detectAppRouterFindings(loadFixtureDir("missing-server-only/negative"));
    expect(findings.filter((f) => f.taxonomy === "M9 — Missing server-only guard")).toHaveLength(0);
  });
});

describe("Server Action missing auth", () => {
  it("flags a 'use server' action that mutates data with no auth check", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-auth/positive"));
    const hits = findings.filter((f) => f.taxonomy === "M9 — Server Action missing auth");

    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "High", category: "Security" });
    expect(hits[0]?.title).toContain("deleteAccount");
  });

  it("does not flag the same action once it checks the caller's session before mutating", () => {
    const findings = detectAppRouterFindings(loadFixtureDir("server-action-auth/negative"));
    expect(taxonomies(findings)).not.toContain("M9 — Server Action missing auth");
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
