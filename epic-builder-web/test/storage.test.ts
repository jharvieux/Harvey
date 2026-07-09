// Proves the Supabase storage adapter (issue #103) round-trips a workspace — session + drafts — through
// Postgres and partitions every row by user_id, with @supabase/supabase-js MOCKED (no live Supabase in
// CI). The fake below is an in-memory stand-in for the two tables with upsert-by-primary-key semantics.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createWorkspace,
  listWorkspaces,
  loadSession,
  readDraft,
  readFileRaw,
  workspaceDir,
  writeDraft,
  writeFile,
} from "../../src/epic-builder/workspace.js";
import { supabaseStore, type SupabaseLike } from "../lib/storage.js";

type Row = Record<string, unknown>;

// In-memory epic_sessions / epic_drafts. select().eq('user_id', …) filters by owner; upsert replaces by
// the table's primary key — exactly the surface lib/storage.ts drives.
class FakeSupabase implements SupabaseLike {
  sessions: Row[] = [];
  drafts: Row[] = [];
  from(table: string) {
    const rows = table === "epic_sessions" ? this.sessions : this.drafts;
    const pk = (r: Row) =>
      table === "epic_sessions" ? `${r.user_id}/${r.slug}` : `${r.user_id}/${r.slug}/${r.path}`;
    return {
      select: () => ({
        eq: (_column: string, value: string) =>
          Promise.resolve({ data: rows.filter((r) => r.user_id === value), error: null }),
      }),
      upsert: (incoming: Row[]) => {
        for (const row of incoming) {
          const i = rows.findIndex((r) => pk(r) === pk(row));
          if (i >= 0) rows[i] = row;
          else rows.push(row);
        }
        return Promise.resolve({ error: null });
      },
    };
  }
}

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "epic-store-"));
}

// A realistic workspace built with the unchanged core: session.json + an epic draft + an intake file +
// a nested story draft.
function seedWorkspace(cwd: string): string {
  const { slug, dir } = createWorkspace(cwd, "Export findings as CSV");
  writeDraft(dir, "epic.md", { data: { kind: "epic", title: "CSV export" }, body: "## Overview\nExport.\n" });
  writeFile(dir, "intake.md", "# Intake\nPrompt.\n");
  writeDraft(dir, "stories/01-endpoint.md", { data: { kind: "story", sequence: 1 }, body: "## AC\n- works\n" });
  return slug;
}

describe("supabase storage adapter", () => {
  it("round-trips a session and its drafts through Postgres", async () => {
    const db = new FakeSupabase();
    const store = supabaseStore(db);
    const userId = "11111111-1111-1111-1111-111111111111";

    const src = tmp();
    const slug = seedWorkspace(src);
    await store.flush(userId, src);

    // Rows landed, keyed by user_id, with state denormalized and drafts (but not session.json) as rows.
    expect(db.sessions).toHaveLength(1);
    expect(db.sessions[0]!.user_id).toBe(userId);
    expect(db.sessions[0]!.slug).toBe(slug);
    expect(db.sessions[0]!.state).toBe("intake");
    const paths = db.drafts.map((r) => r.path).sort();
    expect(paths).toEqual(["epic.md", "intake.md", "stories/01-endpoint.md"]);
    expect(db.drafts.every((r) => r.user_id === userId)).toBe(true);

    // Hydrate into a fresh, empty working copy and assert every file came back intact.
    const dst = tmp();
    await store.hydrate(userId, dst);
    const dir = workspaceDir(dst, slug);
    expect(loadSession(dir).slug).toBe(slug);
    expect(loadSession(dir).state).toBe("intake");
    expect(readDraft(dir, "epic.md").body).toContain("Export.");
    expect(readDraft(dir, "epic.md").data.title).toBe("CSV export");
    expect(readFileRaw(dir, "intake.md")).toContain("Prompt.");
    expect(readDraft(dir, "stories/01-endpoint.md").body).toContain("works");
  });

  it("partitions rows by user_id — one user cannot hydrate another's workspaces", async () => {
    const db = new FakeSupabase();
    const store = supabaseStore(db);
    const alice = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const bob = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    const src = tmp();
    seedWorkspace(src);
    await store.flush(alice, src);

    const bobDir = tmp();
    await store.hydrate(bob, bobDir);
    expect(listWorkspaces(bobDir)).toHaveLength(0);

    const aliceDir = tmp();
    await store.hydrate(alice, aliceDir);
    expect(listWorkspaces(aliceDir)).toHaveLength(1);
  });
});
