// Production dependency assembly for the wrap layer (design §2, §4–§7). Route handlers call
// productionDeps() to get the real model, per-user workspace root, templates, and tracker factory.
// Everything here is server-only — it is imported exclusively from route handlers, never from a
// client component, so no key or token can reach the browser.

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient } from "@supabase/supabase-js";
import { GitHubTracker } from "../../src/trackers/github.js";
import type { Tracker } from "../../src/trackers/types.js";
import { ScaffoldModelClient } from "../../src/epic-builder/model-scaffold.js";
import type { ModelClient } from "../../src/epic-builder/types.js";
import type { Templates } from "../../src/epic-builder/session.js";
import type { CoreDeps } from "./core.js";
import { NoopTracker } from "./core.js";
import { AnthropicModelClient } from "./model-anthropic.js";
import { supabaseStore, type SupabaseLike } from "./storage.js";

function dataRoot(): string {
  return process.env.EPIC_BUILDER_DATA_DIR ?? join(process.cwd(), ".data");
}

function templatesDir(): string {
  return process.env.EPIC_BUILDER_TEMPLATES_DIR ?? join(process.cwd(), "..", "docs", "templates");
}

function loadTemplates(): Templates {
  const read = (name: string) => readFileSync(join(templatesDir(), name), "utf8");
  return { epic: read("epic.md"), story: read("user-story.md"), brief: read("implementation-brief.md") };
}

// The model seam (design §5). Server-side only. Scaffold is the deterministic offline default; the
// live Anthropic client (per docs/design/model-routing.md §6, issue #102) activates when
// EPIC_BUILDER_MODEL=anthropic and a server-side key is present — falls back to the scaffold
// otherwise (missing key, unset/other EPIC_BUILDER_MODEL value). Never constructed from the browser.
function selectModel(): ModelClient {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (process.env.EPIC_BUILDER_MODEL === "anthropic" && apiKey) {
    return new AnthropicModelClient(apiKey);
  }
  return new ScaffoldModelClient();
}

// The tracker factory (design §7). Real run reads the per-engagement token from server env and hands
// it to GitHubTracker, whose private #token field keeps it out of logs/serialization. Dry run needs
// no credentials.
function makeTracker(dryRun: boolean): Tracker {
  if (dryRun) return new NoopTracker();
  const token = requireEnv("GITHUB_TOKEN");
  const owner = requireEnv("GITHUB_OWNER");
  const repo = requireEnv("GITHUB_REPO");
  return new GitHubTracker({ token, owner, repo });
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required to publish (use dry run to preview without it)`);
  return v;
}

// Server-side Supabase client for the storage adapter (design §4). Uses the SERVICE-ROLE key, which is
// never shipped to the browser; the adapter scopes every query by user_id, and RLS guards the anon path.
function supabaseServiceClient(): SupabaseLike {
  const url = requireEnv("SUPABASE_URL");
  const serviceKey = requireEnv("SUPABASE_SERVICE_ROLE_KEY");
  return createClient(url, serviceKey, { auth: { persistSession: false } }) as unknown as SupabaseLike;
}

// Assemble the wrap-layer deps for one authenticated request, partitioned by userId (design §4, §6), plus
// a commit() the route runs after the handler succeeds.
//   - filesystem (default): cwd is the user's durable dir; commit is a no-op (the core writes it directly).
//   - supabase (EPIC_BUILDER_STORAGE=supabase): the user's rows are hydrated into a per-request temp copy,
//     the core runs against it, and commit flushes the copy back to Postgres and removes the temp dir.
export async function productionDeps(
  userId: string,
): Promise<{ deps: CoreDeps; commit: () => Promise<void> }> {
  const base = { model: selectModel(), templates: loadTemplates(), makeTracker };
  if (process.env.EPIC_BUILDER_STORAGE !== "supabase") {
    return { deps: { ...base, cwd: join(dataRoot(), userId) }, commit: async () => {} };
  }
  const store = supabaseStore(supabaseServiceClient());
  const cwd = mkdtempSync(join(tmpdir(), "epic-web-"));
  await store.hydrate(userId, cwd);
  return {
    deps: { ...base, cwd },
    commit: async () => {
      await store.flush(userId, cwd);
      rmSync(cwd, { recursive: true, force: true });
    },
  };
}
