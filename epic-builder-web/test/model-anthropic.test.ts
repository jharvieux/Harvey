// Proves the live Anthropic ModelClient (lib/model-anthropic.ts, issue #102) without a live API
// call: the `@anthropic-ai/sdk` client is mocked, so this asserts each method issues a correctly
// shaped request (model chosen per tier, structured-output schema for the JSON-returning methods)
// and parses the mocked response into the ModelClient return shape. Also proves the deps.ts seam
// (lib/deps.ts `selectModel`, exercised indirectly via `productionDeps`) selects the live client only
// when EPIC_BUILDER_MODEL=anthropic AND a key is present, and falls back to the scaffold otherwise.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DraftStoryInput, ReviseInput } from "../../src/epic-builder/types.js";

const create = vi.fn();

vi.mock("@anthropic-ai/sdk", () => ({
  default: class MockAnthropic {
    messages = { create };
  },
}));

const { AnthropicModelClient } = await import("../lib/model-anthropic.js");

function textResponse(text: string) {
  return { content: [{ type: "text", text }] };
}

beforeEach(() => {
  create.mockReset();
});

describe("AnthropicModelClient", () => {
  it("clarify: sends a json_schema request and parses questions from the response", async () => {
    create.mockResolvedValueOnce(
      textResponse(JSON.stringify({ questions: [{ question: "Who is this for?", assumption: "org admins" }] })),
    );

    const client = new AnthropicModelClient("test-key");
    const result = await client.clarify({ prompt: "Export findings as CSV", round: 1, priorQA: "" }, "standard");

    expect(result).toEqual([{ question: "Who is this for?", assumption: "org admins" }]);
    const call = create.mock.calls[0]![0];
    expect(call.model).toBe("claude-haiku-4-5"); // standard tier
    expect(call.output_config.format.type).toBe("json_schema");
    expect(call.messages[0].content).toContain("Export findings as CSV");
  });

  it("clarify: uses the flagship model on the flagship tier", async () => {
    create.mockResolvedValueOnce(textResponse(JSON.stringify({ questions: [] })));

    const client = new AnthropicModelClient("test-key");
    await client.clarify({ prompt: "x", round: 2, priorQA: "prior" }, "flagship");

    expect(create.mock.calls[0]![0].model).toBe("claude-sonnet-5");
  });

  it("draftEpic: returns the raw text body, no structured-output schema", async () => {
    create.mockResolvedValueOnce(textResponse("# Epic: CSV export\n\n## Overview\nExport findings.\n"));

    const client = new AnthropicModelClient("test-key");
    const body = await client.draftEpic(
      { prompt: "Export findings as CSV", intake: "notes", template: "# Epic: {title}\n\n## Overview\n{summary}\n" },
      "standard",
    );

    expect(body).toContain("CSV export");
    const call = create.mock.calls[0]![0];
    expect(call.model).toBe("claude-haiku-4-5");
    expect(call.output_config).toBeUndefined();
  });

  it("storyManifest: parses entries from a json_schema response", async () => {
    create.mockResolvedValueOnce(
      textResponse(
        JSON.stringify({ entries: [{ title: "Export endpoint", scope: "endpoint", sizing: "M" }] }),
      ),
    );

    const client = new AnthropicModelClient("test-key");
    const entries = await client.storyManifest({ epicBody: "# Epic", intake: "notes" }, "standard");

    expect(entries).toEqual([{ title: "Export endpoint", scope: "endpoint", sizing: "M" }]);
    expect(create.mock.calls[0]![0].output_config.format.schema.properties.entries).toBeDefined();
  });

  it("draftStory: parses body and brief from a json_schema response", async () => {
    create.mockResolvedValueOnce(
      textResponse(JSON.stringify({ body: "# Export endpoint\n", brief: "# Brief\n" })),
    );

    const input: DraftStoryInput = {
      epicBody: "# Epic",
      intake: "notes",
      entry: { title: "Export endpoint", scope: "endpoint", sizing: "M" },
      siblingTitles: ["Permission filter"],
      storyTemplate: "# {title}\n",
      briefTemplate: "# Brief: {title}\n",
    };

    const client = new AnthropicModelClient("test-key");
    const result = await client.draftStory(input, "flagship");

    expect(result).toEqual({ body: "# Export endpoint\n", brief: "# Brief\n" });
    expect(create.mock.calls[0]![0].model).toBe("claude-sonnet-5");
  });

  it("revise: returns the revised body as plain text, prompt carries instruction and comments", async () => {
    create.mockResolvedValueOnce(textResponse("# Epic\n\nRevised body.\n"));

    const input: ReviseInput = {
      current: "# Epic\n\n> [!comment] tighten this\nOriginal body.\n",
      instruction: "tighten scope",
      comments: ["tighten this"],
    };

    const client = new AnthropicModelClient("test-key");
    const body = await client.revise(input, "standard");

    expect(body).toBe("# Epic\n\nRevised body.");
    const call = create.mock.calls[0]![0];
    expect(call.messages[0].content).toContain("tighten scope");
    expect(call.messages[0].content).toContain("tighten this");
  });

  it("throws a clear error when the response has no text content block", async () => {
    create.mockResolvedValueOnce({ content: [] });

    const client = new AnthropicModelClient("test-key");
    await expect(client.draftEpic({ prompt: "x", intake: "", template: "" }, "standard")).rejects.toThrow(
      /no text content/,
    );
  });
});

describe("selectModel (lib/deps.ts)", () => {
  const ORIGINAL_ENV = { ...process.env };

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    vi.resetModules();
  });

  it("selects the live Anthropic client when EPIC_BUILDER_MODEL=anthropic and a key is present", async () => {
    process.env.EPIC_BUILDER_MODEL = "anthropic";
    process.env.ANTHROPIC_API_KEY = "test-key";
    vi.resetModules();
    const { productionDeps } = await import("../lib/deps.js");
    const { AnthropicModelClient: LiveClient } = await import("../lib/model-anthropic.js");
    expect(productionDeps().model).toBeInstanceOf(LiveClient);
  });

  it("falls back to the scaffold when EPIC_BUILDER_MODEL is unset", async () => {
    delete process.env.EPIC_BUILDER_MODEL;
    process.env.ANTHROPIC_API_KEY = "test-key";
    vi.resetModules();
    const { productionDeps } = await import("../lib/deps.js");
    const { ScaffoldModelClient } = await import("../../src/epic-builder/model-scaffold.js");
    expect(productionDeps().model).toBeInstanceOf(ScaffoldModelClient);
  });

  it("falls back to the scaffold when EPIC_BUILDER_MODEL=anthropic but no key is present", async () => {
    process.env.EPIC_BUILDER_MODEL = "anthropic";
    delete process.env.ANTHROPIC_API_KEY;
    vi.resetModules();
    const { productionDeps } = await import("../lib/deps.js");
    const { ScaffoldModelClient } = await import("../../src/epic-builder/model-scaffold.js");
    expect(productionDeps().model).toBeInstanceOf(ScaffoldModelClient);
  });
});
