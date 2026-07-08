// Default offline ModelClient (design §7 seam). It fills the templates deterministically from the
// prompt and intake — no network, no provider dependency — so `pnpm epic` runs end-to-end today and
// the operator can edit/comment the scaffolded drafts. Wiring a live model (the #19 router) means
// supplying a different ModelClient; nothing else changes. Tests use their own bespoke fakes.

import { parseFrontmatter } from "./frontmatter.js";
import type {
  ClarifyQuestion,
  DraftStoryInput,
  DraftStoryResult,
  ModelClient,
  ReviseInput,
  StoryManifestEntry,
} from "./types.js";

function templateBody(template: string, title: string): string {
  const { body } = parseFrontmatter(template);
  return body.replace(/\{title\}/g, title).replace(/\{[^}]+\}/g, "TODO");
}

function inScopeBullets(epicBody: string): string[] {
  const lines = epicBody.split("\n");
  const bullets: string[] = [];
  let inScope = false;
  for (const line of lines) {
    if (line.startsWith("## ")) inScope = /in scope/i.test(line) && !/out of scope/i.test(line);
    else if (inScope) {
      const m = /^[-*]\s+(.+)$/.exec(line.trim());
      if (m && !/^TODO/.test(m[1]!)) bullets.push(m[1]!.replace(/\(candidate stories.*/i, "").trim());
    }
  }
  return bullets;
}

export class ScaffoldModelClient implements ModelClient {
  async clarify(input: { prompt: string; round: number }): Promise<ClarifyQuestion[]> {
    if (input.round > 1) return [];
    return [
      { question: "Who is the primary user of this capability?", assumption: "org admins" },
      { question: "What is the single most important success metric?", assumption: "adoption within 30 days" },
      { question: "Any hard constraints (compliance, latency, data residency)?", assumption: "none beyond existing platform norms" },
    ];
  }

  async draftEpic(input: { prompt: string; template: string }): Promise<string> {
    const title = input.prompt.length > 60 ? `${input.prompt.slice(0, 57)}...` : input.prompt;
    const body = templateBody(input.template, title);
    return body.replace(
      "One or two sentences: the user/business problem and the outcome this epic delivers.",
      `${input.prompt}`,
    );
  }

  async storyManifest(input: { epicBody: string }): Promise<StoryManifestEntry[]> {
    const bullets = inScopeBullets(input.epicBody);
    const source = bullets.length ? bullets : ["Implement the core capability"];
    return source.map((scope) => ({ title: scope, scope, sizing: "M" }));
  }

  async draftStory(input: DraftStoryInput): Promise<DraftStoryResult> {
    return {
      body: templateBody(input.storyTemplate, input.entry.title),
      brief: templateBody(input.briefTemplate, input.entry.title),
    };
  }

  // The scaffold cannot semantically revise. Per the §4.3 contract it never silently drops a
  // comment: it replaces each with a `> [!note] AI:` explaining that a real model is required, so
  // no `> [!comment]` block survives and the reviewer knows to edit directly or wire a live model.
  async revise(input: ReviseInput): Promise<string> {
    let body = input.current.replace(
      /^> \[!comment\][\s\S]*?(?=\n(?!>)|\n?$)/gm,
      "> [!note] AI: scaffold model cannot auto-revise this comment — edit the file directly or wire a live model.",
    );
    if (input.instruction) {
      body += `\n\n> [!note] AI: instruction recorded for a live model: ${input.instruction}\n`;
    }
    return body;
  }
}
