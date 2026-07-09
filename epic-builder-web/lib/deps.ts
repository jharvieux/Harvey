// Production dependency assembly for the wrap layer (design §2, §4–§7). Route handlers call
// productionDeps() to get the real model, per-user workspace root, templates, and tracker factory.
// Everything here is server-only — it is imported exclusively from route handlers, never from a
// client component, so no key or token can reach the browser.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { GitHubTracker } from "../../src/trackers/github.js";
import type { Tracker } from "../../src/trackers/types.js";
import { ScaffoldModelClient } from "../../src/epic-builder/model-scaffold.js";
import type { ModelClient } from "../../src/epic-builder/types.js";
import type { Templates } from "../../src/epic-builder/session.js";
import type { CoreDeps } from "./core.js";
import { NoopTracker } from "./core.js";
import { AnthropicModelClient } from "./model-anthropic.js";

// The single operator partition in the MVP (design §6). Becomes the Supabase user id in production.
const OPERATOR = "operator";

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

export function productionDeps(): CoreDeps {
  return {
    model: selectModel(),
    cwd: join(dataRoot(), OPERATOR),
    templates: loadTemplates(),
    makeTracker,
  };
}
