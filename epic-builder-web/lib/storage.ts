// Supabase-Postgres durable store for the workspace seam (design epic-builder-web.md §4, issue #103).
//
// The core (src/epic-builder) persists a workspace as a synchronous filesystem tree and cannot be made
// async without changing it — and src/ is off-limits here. So this adapter does not replace the fs seam
// call-by-call; it bridges it: a request HYDRATES the user's rows into a per-request temp working copy,
// the unchanged core runs synchronously against that copy, then the request FLUSHES the copy back to
// Postgres. The durable, user-partitioned source of truth is Supabase; the temp dir is ephemeral scratch
// (which is exactly what a serverless filesystem is good for — resolving the §4 "ephemeral fs" caveat).
//
// Every query is scoped by user_id, so the adapter never crosses tenants even though the service-role key
// bypasses RLS; RLS (see supabase/migrations) is the defense-in-depth for the anon-key client path.

import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import type { DraftSession } from "../../src/epic-builder/types.js";
import { listWorkspaces, loadSession, workspaceDir } from "../../src/epic-builder/workspace.js";

// The slice of the supabase-js client this adapter uses. Narrow on purpose: production passes the real
// SupabaseClient (structurally wider), tests pass an in-memory fake — neither needs the full surface.
type Row = Record<string, unknown>;
interface SupabaseError {
  message: string;
}
export interface SupabaseLike {
  from(table: string): {
    select(columns: string): {
      eq(column: string, value: string): PromiseLike<{ data: Row[] | null; error: SupabaseError | null }>;
    };
    upsert(rows: Row[]): PromiseLike<{ error: SupabaseError | null }>;
  };
}

export interface DurableStore {
  /** Materialize every workspace owned by userId into cwd as the fs tree the core expects. */
  hydrate(userId: string, cwd: string): Promise<void>;
  /** Persist every workspace under cwd back to Postgres, scoped to userId. */
  flush(userId: string, cwd: string): Promise<void>;
}

const SESSIONS = "epic_sessions";
const DRAFTS = "epic_drafts";

export function supabaseStore(client: SupabaseLike): DurableStore {
  return {
    async hydrate(userId, cwd) {
      const sessions = unwrap(await client.from(SESSIONS).select("slug, json").eq("user_id", userId));
      const drafts = unwrap(await client.from(DRAFTS).select("slug, path, body").eq("user_id", userId));
      for (const s of sessions) {
        const dir = workspaceDir(cwd, String(s.slug));
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, "session.json"), `${JSON.stringify(s.json, null, 2)}\n`);
      }
      for (const d of drafts) {
        const target = join(workspaceDir(cwd, String(d.slug)), String(d.path));
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, String(d.body));
      }
    },

    async flush(userId, cwd) {
      const sessionRows: Row[] = [];
      const draftRows: Row[] = [];
      for (const { slug } of listWorkspaces(cwd)) {
        const dir = workspaceDir(cwd, slug);
        const session: DraftSession = loadSession(dir);
        sessionRows.push({ user_id: userId, slug, state: session.state, json: session });
        for (const rel of walkFiles(dir)) {
          if (rel === "session.json") continue;
          draftRows.push({ user_id: userId, slug, path: rel, body: readFileSync(join(dir, rel), "utf8") });
        }
      }
      if (sessionRows.length) throwOn(await client.from(SESSIONS).upsert(sessionRows));
      if (draftRows.length) throwOn(await client.from(DRAFTS).upsert(draftRows));
    },
  };
}

function unwrap(res: { data: Row[] | null; error: SupabaseError | null }): Row[] {
  if (res.error) throw new Error(`supabase read failed: ${res.error.message}`);
  return res.data ?? [];
}

function throwOn(res: { error: SupabaseError | null }): void {
  if (res.error) throw new Error(`supabase write failed: ${res.error.message}`);
}

// Every file under a workspace dir, as workspace-relative POSIX paths (the shape stored in epic_drafts).
function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const abs = join(entry.parentPath, entry.name);
    out.push(relative(dir, abs).split(sep).join("/"));
  }
  return out;
}
