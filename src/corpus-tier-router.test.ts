import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WORKFLOW = fileURLToPath(new URL("../.github/workflows/corpus-drift.yml", import.meta.url));

function routeScript(yaml: string = readFileSync(WORKFLOW, "utf8")): string {
  const marker = "      - name: Generate live corpus ownership and classify the exact Git range\n        id: route\n";
  const markerStart = yaml.indexOf(marker);
  if (markerStart === -1) throw new Error("corpus relevance route step is absent");
  const runMarker = "        run: |\n";
  const runStart = yaml.indexOf(runMarker, markerStart);
  const bodyStart = runStart + runMarker.length;
  const bodyEnd = yaml.indexOf("\n      - ", bodyStart);
  if (runStart === -1 || bodyEnd === -1) throw new Error("corpus relevance route script is malformed");
  const body = yaml.slice(bodyStart, bodyEnd).replace(/^ {10}/gm, "");
  for (const fragment of [
    "corpus-drift-relevance.ts ownership",
    "corpus-drift-relevance.ts classify",
    'if [ "$EVENT_NAME" = pull_request ] || [ "$EVENT_NAME" = merge_group ]',
    "decision=unconditional-full",
    'echo "relevant=$relevant"',
  ]) {
    if (!body.includes(fragment)) throw new Error(`corpus relevance route is missing ${fragment}`);
  }
  return body;
}

describe("corpus hosted relevance router", () => {
  it("derives PR and merge-group routing from the shipping ownership/classifier CLI", () => {
    const yaml = readFileSync(WORKFLOW, "utf8");
    const script = routeScript(yaml);

    expect(script.indexOf("corpus-drift-relevance.ts ownership"))
      .toBeLessThan(script.indexOf("corpus-drift-relevance.ts classify"));
    expect(script).toContain('--root "$GITHUB_WORKSPACE"');
    expect(script).toContain('--base "$base"');
    expect(script).toContain('--head "$HEAD_SHA"');
    expect(script).toContain('--ownership "$ownership"');
    expect(yaml).not.toContain("Route third-party corpus execution by event");
    expect(yaml).not.toContain("PR and merge-group policy defers all third-party corpus execution");
  });

  it("fails open to a full pinned run and bypasses classification for non-PR events", () => {
    const script = routeScript();
    expect(script).toContain("select(. == \"full-scan\" or . == \"declared-no-op\")");
    expect(script).toContain('if [ "$decision" = full-scan ]');
    expect(script).toContain("decision=unconditional-full");
    expect(script).toContain("relevant=true");
    expect(script).toContain('scope="all $target_count pinned targets; $EVENT_NAME bypasses PR relevance classification"');
  });

  it("keeps the steady schedule plus the bounded #1883 live-OSV acceptance window", () => {
    const yaml = readFileSync(WORKFLOW, "utf8");
    const crons = [...yaml.matchAll(/^\s*-\s*cron:\s*"([^"]+)"/gm)].map((match) => match[1]!);
    expect(crons, "the repair must retain daily coverage and only the approved 2026-09-01 acceptance slots").toEqual([
      "23 7 * * *",
      "13 19,20,21 1 9 *",
    ]);
    expect(crons.every((cron) => cron.split(" ")[0] !== "0"), "GitHub can delay or drop minute-zero schedules under high Actions load").toBe(true);
    expect(yaml).not.toContain("13,28,43,58 19 28 8 *");
    expect(yaml).toContain("TEMPORARY #1883 live-OSV repair acceptance");
    expect(yaml).toContain("remove after the first accepted 2026-09-01");
  });

  it("allocates shards only for relevant receipts and keeps required-context liveness explicit", () => {
    const yaml = readFileSync(WORKFLOW, "utf8");
    expect(yaml).toContain("if: needs.prepare-current-inputs.result == 'success' && needs.prepare-current-inputs.outputs.relevant == 'true'");
    expect(yaml).toContain("name: Declare the proven-disjoint no-op");
    expect(yaml).toContain("status: declared-no-op");
    expect(yaml).toContain("name: Record the measured full-population outcome");
    expect(yaml).toContain("units: ${{ needs.prepare-current-inputs.outputs.target-count }}");
    expect(yaml).toContain("name: Gate liveness — did this required context declare its outcome?\n        if: always()");
  });

  it("refuses the superseded blanket event router as a production proof", () => {
    expect(() => routeScript("jobs:\n  shard:\n    steps:\n      - name: Route third-party corpus execution by event\n"))
      .toThrow(/route step is absent/);
  });
});
