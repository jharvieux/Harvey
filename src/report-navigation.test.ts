import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { assertFindingNavigation } from "../report-template/navigation.mjs";
import type { FindingsDocument } from "./findings.js";
import { renderFidelityBreaches } from "./render-fidelity.js";

const fixture = JSON.parse(readFileSync(new URL("./__fixtures__/report-navigation.json", import.meta.url), "utf8")) as FindingsDocument & { fixHandoff: Record<string, unknown> };

describe("report finding navigation", () => {
  it("links each summary to a unique full detail, including grouped members and fix delivery", () => {
    const html = buildHtml(fixture);
    const links = [...html.matchAll(/<a class="finding-link" href="#([^"]+)" data-finding-link="([^"]+)"/g)];
    expect(links).toHaveLength(49); // six recommendations, forty actions, three handoff references
    expect(new Set(links.map((x) => x[2])).size).toBe(43);
    expect(html).toContain('class="linked-findings"');
    expect(html).toContain("EVIDENCE44"); // member outside both top-six and action cap, linked by handoff
    expect(html).toContain("REMEDY44");
    expect(html).toContain("NOT-IN-REPORT (details not in this report)");
    expect(html).toContain("4 more High finding(s) of this shape are not individually rendered");
    expect(html).toContain("+ 5 more qualifying action(s)");
    expect(html).toContain(".finding-link:focus-visible");
    expect(() => assertFindingNavigation(html)).not.toThrow();
    expect(renderFidelityBreaches(fixture, html)).toEqual([]);
  });

  it("keeps exact identities stable under reorder, escaped punctuation, Unicode, suffixes and duplicate titles", () => {
    const destinations = (html: string) => [...html.matchAll(/id="(finding-[^"]+)" data-finding-id="([^"]+)"/g)]
      .map((m) => [m[2], m[1]]).sort(([a], [b]) => (a ?? "").localeCompare(b ?? ""));
    // Make every member a handoff reference so sorting changes do not change which cards are promoted.
    const allLinked = { ...fixture, fixHandoff: { ...fixture.fixHandoff!, rows: fixture.findings.map((f) => ({ findingId: f.id, status: "manual" as const, reason: "Fixture" })) } };
    expect(destinations(buildHtml(allLinked))).toEqual(destinations(buildHtml({ ...allLinked, findings: [...fixture.findings].reverse() })));
    const ids = destinations(buildHtml(allLinked)).map(([, id]) => id);
    expect(new Set(ids).size).toBe(fixture.findings.length);
    expect(ids.every((id) => /^finding-[a-f0-9]+$/.test(id ?? ""))).toBe(true);
    expect(buildHtml(allLinked)).toContain('data-finding-id="quoted&quot;&lt;&amp;&gt; / 雪"');
    expect(() => buildHtml({ ...fixture, findings: [fixture.findings[0]!, fixture.findings[0]!] })).toThrow(/unique identities/);
  });

  it("rejects a deleted, ambiguous or misbound destination in the emitted report", () => {
    const html = buildHtml(fixture);
    const anchor = /href="#([^"]+)"/.exec(html)![1]!;
    expect(() => assertFindingNavigation(html.replace(`id="${anchor}"`, 'id="deleted"'))).toThrow(/no unique intended detail/);
    expect(() => assertFindingNavigation(html.replace(`href="#${anchor}"`, 'href="#finding-mismatched"'))).toThrow(/no unique intended detail/);
    const destination = /id="finding-[^"]+" data-finding-id="[^"]+"/.exec(html)![0];
    expect(() => assertFindingNavigation(html + `<div ${destination}></div>`)).toThrow(/Duplicate/);
    expect(() => assertFindingNavigation(html.replace(destination, destination.replace(/data-finding-id="[^"]+"/, 'data-finding-id="wrong-member"')))).toThrow(/no unique intended detail/);
  });
});
