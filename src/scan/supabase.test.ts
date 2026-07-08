import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runSupabaseScan } from "./supabase.js";

function mockFetch(responses: {
  advisors: unknown;
  authConfig: unknown;
  tables: unknown;
  extensions: unknown;
  buckets: unknown;
  policies: unknown;
}): typeof fetch {
  return vi.fn(async (url: string | URL, init?: RequestInit) => {
    const u = url.toString();
    if (u.includes("/advisors/security")) return new Response(JSON.stringify(responses.advisors));
    if (u.includes("/config/auth")) return new Response(JSON.stringify(responses.authConfig));
    if (u.includes("/database/query")) {
      const body = JSON.parse(String(init?.body ?? "{}")) as { query: string };
      if (body.query.includes("pg_tables")) return new Response(JSON.stringify(responses.tables));
      if (body.query.includes("pg_extension")) return new Response(JSON.stringify(responses.extensions));
      if (body.query.includes("storage.buckets")) return new Response(JSON.stringify(responses.buckets));
      if (body.query.includes("pg_policies")) return new Response(JSON.stringify(responses.policies));
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
}

describe("runSupabaseScan", () => {
  it("throws when neither projectRef nor local is given", async () => {
    await expect(runSupabaseScan({ managementApiToken: "t" })).rejects.toThrow(/requires projectRef/);
  });

  it("throws when no Management API token is available", async () => {
    await expect(runSupabaseScan({ projectRef: "abc", managementApiToken: "" })).rejects.toThrow(/token required/);
  });

  it("merges advisor, auth-config, table, extension, and bucket findings from a hosted scan", async () => {
    const fetchImpl = mockFetch({
      advisors: { lints: [{ name: "rls_disabled_in_public", title: "RLS Disabled in Public", level: "ERROR", metadata: { name: "orders", schema: "public" } }] },
      authConfig: { mailer_autoconfirm: true },
      tables: [{ schema: "public", name: "widgets", rlsEnabled: false }],
      extensions: [{ name: "pg_net", schema: "extensions", installed_version: "0.20.3" }],
      buckets: [{ id: "b1", name: "avatars", public: true }],
      policies: [],
    });

    const findings = await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl });
    const taxonomies = findings.map((f) => f.taxonomy);

    expect(taxonomies).toContain("rls_disabled_in_public");
    expect(taxonomies).toContain("Auth config: email confirmation disabled");
    expect(taxonomies).toContain("Auto-exposed public-schema table");
    expect(taxonomies).toContain("Dangerous extension enabled");
    expect(taxonomies).toContain("Public bucket with no policies");
    expect(findings.every((f) => f.mechanical)).toBe(true);
  });

  it("propagates a Management API error instead of swallowing it", async () => {
    const fetchImpl = vi.fn(async () => new Response("forbidden", { status: 403 })) as unknown as typeof fetch;
    await expect(runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl })).rejects.toThrow(/403/);
  });

  describe("functionsDir", () => {
    let dir: string;
    afterEach(() => rmSync(dir, { recursive: true, force: true }));

    it("also runs edge-function secret/webhook checks when functionsDir is given", async () => {
      dir = mkdtempSync(join(tmpdir(), "harvey-edge-fns-"));
      mkdirSync(join(dir, "stripe-webhook"));
      writeFileSync(join(dir, "stripe-webhook", "index.ts"), `export default async (req) => { await req.json(); };`);

      const fetchImpl = mockFetch({
        advisors: { lints: [] },
        authConfig: {},
        tables: [],
        extensions: [],
        buckets: [],
        policies: [],
      });
      const findings = await runSupabaseScan({ projectRef: "abc123", managementApiToken: "t", fetchImpl, functionsDir: dir });
      expect(findings.some((f) => f.taxonomy === "Unsigned/unverified webhook handler")).toBe(true);
    });
  });
});
