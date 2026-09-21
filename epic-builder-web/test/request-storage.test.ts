import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createWorkspace, listWorkspaces, loadSession, workspaceDir, writeDraft } from "../../src/epic-builder/workspace.js";
import { resolveUserId } from "../lib/auth.js";
import { productionDeps } from "../lib/deps.js";
import { handle } from "../lib/route.js";

const client = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("../lib/auth.js", () => ({ resolveUserId: vi.fn() }));
vi.mock("@supabase/supabase-js", () => ({ createClient: (...args: unknown[]) => client.createClient(...args) }));

type Row = Record<string, unknown>;
type Table = "epic_sessions" | "epic_drafts";
class LocalSupabase {
  sessions: Row[] = [];
  drafts: Row[] = [];
  reads: { table: string; columns: string; filter: string; userId: string }[] = [];
  writes: { table: string; rows: Row[] }[] = [];
  readError: Table | null = null;
  writeError: Table | null = null;

  from(table: string) {
    const target = table === "epic_sessions" ? this.sessions : this.drafts;
    return {
      select: (columns: string) => ({
        eq: async (filter: string, userId: string) => {
          this.reads.push({ table, columns, filter, userId });
          if (this.readError === table) return { data: null, error: { message: "hydrate denied" } };
          return { data: target.filter((row) => filter === "user_id" && row.user_id === userId), error: null };
        },
      }),
      upsert: async (rows: Row[]) => {
        this.writes.push({ table, rows });
        if (this.writeError === table) return { error: { message: "upsert denied" } };
        for (const row of rows) {
          const key = table === "epic_sessions" ? ["user_id", "slug"] : ["user_id", "slug", "path"];
          const index = target.findIndex((saved) => key.every((column) => saved[column] === row[column]));
          if (index < 0) target.push(row);
          else target[index] = row;
        }
        return { error: null };
      },
    };
  }
}

let db: LocalSupabase;
let scratchBefore: Set<string>;
let dataDir: string;
const scratchDirs = () => new Set(readdirSync(tmpdir()).filter((name) => name.startsWith("epic-web-")));

beforeEach(() => {
  db = new LocalSupabase();
  scratchBefore = scratchDirs();
  dataDir = mkdtempSync(join(tmpdir(), "epic-deps-data-"));
  client.createClient.mockReset().mockReturnValue(db);
  vi.mocked(resolveUserId).mockReset().mockResolvedValue("user-a");
  vi.stubEnv("EPIC_BUILDER_STORAGE", "supabase");
  vi.stubEnv("EPIC_BUILDER_MODEL", "");
  vi.stubEnv("EPIC_BUILDER_TEMPLATES_DIR", resolve(process.cwd(), "../docs/templates"));
  vi.stubEnv("EPIC_BUILDER_DATA_DIR", dataDir);
  vi.stubEnv("SUPABASE_URL", "https://fixture.invalid");
  vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "fixture-service-key");
});
afterEach(() => {
  vi.unstubAllEnvs();
  expect(scratchDirs()).toEqual(scratchBefore);
  rmSync(dataDir, { recursive: true, force: true });
});

function saveFixture(cwd: string): string {
  const { slug, dir } = createWorkspace(cwd, "A local request fixture");
  writeDraft(dir, "epic.md", { data: { title: "Fixture" }, body: "A draft." });
  return slug;
}

describe("real request dependency assembly and storage", () => {
  it("uses the filesystem user partition without a temporary Supabase resource", async () => {
    vi.stubEnv("EPIC_BUILDER_STORAGE", "");
    const acquired = await productionDeps("user-b");
    expect(acquired.deps.cwd).toBe(join(dataDir, "user-b"));
    expect(client.createClient).not.toHaveBeenCalled();
    await acquired.commit();
    await acquired.release();
  });

  it("hydrates only verified-user rows, flushes once and releases scratch after success", async () => {
    const other = { slug: "other", path: "epic.md", body: "private", user_id: "user-b" };
    db.drafts.push(other);
    const first = await handle(async (deps) => {
      expect(deps.cwd).not.toBe(join(dataDir, "user-a"));
      const slug = saveFixture(deps.cwd);
      return { slug };
    });
    expect(first.status).toBe(200);
    const { slug } = await first.json() as { slug: string };
    expect(db.reads).toEqual([
      { table: "epic_sessions", columns: "slug, json", filter: "user_id", userId: "user-a" },
      { table: "epic_drafts", columns: "slug, path, body", filter: "user_id", userId: "user-a" },
    ]);
    expect(db.writes.map((write) => write.table)).toEqual(["epic_sessions", "epic_drafts"]);
    expect(db.writes.every((write) => write.rows.every((row) => row.user_id === "user-a"))).toBe(true);
    expect(db.drafts).toContain(other);
    expect(db.sessions).toHaveLength(1);
    expect(db.sessions[0]!.slug).toBe(slug);
    expect(client.createClient).toHaveBeenCalledWith(
      "https://fixture.invalid", "fixture-service-key", { auth: { persistSession: false } },
    );
    const second = await handle(async (deps) => ({ state: loadSession(workspaceDir(deps.cwd, slug)).state }));
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual({ state: "intake" });
    expect(db.writes).toHaveLength(4);
    vi.mocked(resolveUserId).mockResolvedValueOnce("user-b");
    const partition = await handle(async (deps) => ({ workspaces: listWorkspaces(deps.cwd) }));
    expect(partition.status).toBe(200);
    expect((await partition.json() as { workspaces: unknown[] }).workspaces).toEqual([]);
  });

  it("denies before constructing a service client or acquiring scratch", async () => {
    vi.mocked(resolveUserId).mockResolvedValueOnce(null);
    const work = vi.fn();
    const res = await handle(work);
    expect(res.status).toBe(401);
    expect(work).not.toHaveBeenCalled();
    expect(client.createClient).not.toHaveBeenCalled();
  });

  it("does not start core or flush when either hydrate query fails, and releases scratch", async () => {
    for (const table of ["epic_sessions", "epic_drafts"] as const) {
      db.readError = table;
      const work = vi.fn();
      const res = await handle(work);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "supabase read failed: hydrate denied" });
      expect(work).not.toHaveBeenCalled();
      expect(db.writes).toHaveLength(0);
      db.readError = null;
    }
  });

  it("does not flush a failed handler but releases its acquired scratch", async () => {
    const res = await handle(async (deps) => {
      saveFixture(deps.cwd);
      throw new Error("controlled handler failure");
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "controlled handler failure" });
    expect(db.writes).toHaveLength(0);
  });

  it("surfaces either table upsert failure and releases scratch after a failed flush", async () => {
    for (const table of ["epic_sessions", "epic_drafts"] as const) {
      db.writeError = table;
      const res = await handle(async (deps) => {
        saveFixture(deps.cwd);
        return { ok: true };
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "supabase write failed: upsert denied" });
      expect(db.writes.at(-1)?.table).toBe(table);
      db.writeError = null;
      db.writes = [];
      db.sessions = [];
      db.drafts = [];
    }
  });
});
