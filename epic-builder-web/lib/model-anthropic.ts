// Live Anthropic ModelClient (design docs/design/epic-builder-web.md §5, §9; issue #102). Server-side
// only — reads ANTHROPIC_API_KEY from the environment and is constructed exclusively in deps.ts, so
// the key never reaches the browser. Honors the `Tier` argument tier-policy.ts threads through every
// call: standard -> Haiku 4.5, flagship -> Sonnet 5 (per docs/design/model-routing.md §6). `bulk` has
// no ModelTask mapping to it today (tier-policy.ts's BASE_TIER only ever yields "standard" or
// "flagship") but is handled defensively so the map stays total over `Tier`.

import Anthropic from "@anthropic-ai/sdk";
import type {
  ClarifyQuestion,
  DraftStoryInput,
  DraftStoryResult,
  ModelClient,
  ReviseInput,
  StoryManifestEntry,
  Tier,
} from "../../src/epic-builder/types.js";

const MODEL_FOR_TIER: Record<Tier, string> = {
  bulk: "claude-haiku-4-5",
  standard: "claude-haiku-4-5",
  flagship: "claude-sonnet-5",
};

function textOf(content: Anthropic.ContentBlock[]): string {
  const block = content.find((b): b is Anthropic.TextBlock => b.type === "text");
  if (!block) throw new Error("Anthropic response contained no text content block");
  return block.text;
}

function parseJson<T>(text: string): T {
  return JSON.parse(text) as T;
}

const clarifySchema = {
  type: "object",
  properties: {
    questions: {
      type: "array",
      items: {
        type: "object",
        properties: {
          question: { type: "string" },
          assumption: { type: "string" },
        },
        required: ["question", "assumption"],
        additionalProperties: false,
      },
    },
  },
  required: ["questions"],
  additionalProperties: false,
} as const;

const storyManifestSchema = {
  type: "object",
  properties: {
    entries: {
      type: "array",
      items: {
        type: "object",
        properties: {
          title: { type: "string" },
          scope: { type: "string" },
          sizing: { type: "string", enum: ["S", "M", "L"] },
        },
        required: ["title", "scope", "sizing"],
        additionalProperties: false,
      },
    },
  },
  required: ["entries"],
  additionalProperties: false,
} as const;

const draftStorySchema = {
  type: "object",
  properties: {
    body: { type: "string" },
    brief: { type: "string" },
  },
  required: ["body", "brief"],
  additionalProperties: false,
} as const;

export class AnthropicModelClient implements ModelClient {
  readonly #client: Anthropic;

  constructor(apiKey: string) {
    this.#client = new Anthropic({ apiKey });
  }

  async clarify(
    input: { prompt: string; round: number; priorQA: string },
    tier: Tier,
  ): Promise<ClarifyQuestion[]> {
    const response = await this.#client.messages.create({
      model: MODEL_FOR_TIER[tier],
      max_tokens: 1024,
      output_config: { format: { type: "json_schema", schema: clarifySchema } },
      messages: [
        {
          role: "user",
          content: [
            "You are drafting clarifying questions for a software epic before it is written.",
            `Epic prompt: ${input.prompt}`,
            input.priorQA
              ? `Prior clarifying Q&A:\n${input.priorQA}`
              : "This is round 1 — there is no prior Q&A yet.",
            input.round > 1
              ? "Only ask further questions if something material is still unresolved after the prior round; return an empty list if the prompt is already clear enough to draft."
              : "Ask up to 3 clarifying questions. Each needs a reasonable default assumption a reviewer could accept as-is without answering.",
          ].join("\n\n"),
        },
      ],
    });
    return parseJson<{ questions: ClarifyQuestion[] }>(textOf(response.content)).questions;
  }

  async draftEpic(
    input: { prompt: string; intake: string; template: string },
    tier: Tier,
  ): Promise<string> {
    const response = await this.#client.messages.create({
      model: MODEL_FOR_TIER[tier],
      max_tokens: 4096,
      messages: [
        {
          role: "user",
          content: [
            "Draft a software epic in Markdown, following the section structure of the template below exactly (same headings, same order). Replace every {placeholder} with real content grounded in the prompt and intake notes. Do not leave any template placeholder syntax in the output.",
            `Template:\n${input.template}`,
            `Epic prompt: ${input.prompt}`,
            `Intake notes:\n${input.intake}`,
            "Respond with only the Markdown body — no commentary before or after it.",
          ].join("\n\n"),
        },
      ],
    });
    return textOf(response.content).trim();
  }

  async storyManifest(
    input: { epicBody: string; intake: string },
    tier: Tier,
  ): Promise<StoryManifestEntry[]> {
    const response = await this.#client.messages.create({
      model: MODEL_FOR_TIER[tier],
      max_tokens: 2048,
      output_config: { format: { type: "json_schema", schema: storyManifestSchema } },
      messages: [
        {
          role: "user",
          content: [
            "Split the epic below into a manifest of user stories. Each story needs a short title, a one-line scope description, and a T-shirt sizing (S/M/L) estimate.",
            `Epic:\n${input.epicBody}`,
            `Intake notes:\n${input.intake}`,
          ].join("\n\n"),
        },
      ],
    });
    return parseJson<{ entries: StoryManifestEntry[] }>(textOf(response.content)).entries;
  }

  async draftStory(input: DraftStoryInput, tier: Tier): Promise<DraftStoryResult> {
    const response = await this.#client.messages.create({
      model: MODEL_FOR_TIER[tier],
      max_tokens: 4096,
      output_config: { format: { type: "json_schema", schema: draftStorySchema } },
      messages: [
        {
          role: "user",
          content: [
            "Draft a user story and its implementation brief in Markdown, following the section structure of each template below exactly. Replace every {placeholder} with real content grounded in the epic, intake notes, and story entry.",
            `Story template:\n${input.storyTemplate}`,
            `Implementation brief template:\n${input.briefTemplate}`,
            `Epic:\n${input.epicBody}`,
            `Intake notes:\n${input.intake}`,
            `Story entry: ${JSON.stringify(input.entry)}`,
            input.siblingTitles.length
              ? `Sibling stories in this epic — keep scope distinct from these: ${input.siblingTitles.join(", ")}`
              : "No sibling stories.",
          ].join("\n\n"),
        },
      ],
    });
    return parseJson<DraftStoryResult>(textOf(response.content));
  }

  async revise(input: ReviseInput, tier: Tier): Promise<string> {
    const response = await this.#client.messages.create({
      model: MODEL_FOR_TIER[tier],
      max_tokens: 4096,
      messages: [
        {
          role: "user",
          content: [
            "Revise the Markdown draft below. Resolve every `> [!comment]` block by acting on it and removing the comment marker — a revision must not leave any `> [!comment]` block behind.",
            input.instruction ? `Instruction: ${input.instruction}` : "No additional one-line instruction.",
            input.comments.length
              ? `Standalone comments to resolve:\n${input.comments.join("\n---\n")}`
              : "No standalone comments.",
            `Current draft:\n${input.current}`,
            "Respond with only the full revised Markdown body — no commentary before or after it.",
          ].join("\n\n"),
        },
      ],
    });
    return textOf(response.content).trim();
  }
}
