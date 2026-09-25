import { describe, expect, it } from "vitest";
import { parseFrontmatter, serializeFrontmatter, type FrontmatterData } from "./frontmatter.js";

describe("frontmatter", () => {
  it("round-trips the builder's draft frontmatter shape", () => {
    const data: FrontmatterData = {
      kind: "story",
      epic: "csv-export",
      sequence: 2,
      title: "Filter exported rows by viewer permissions",
      status: "in-review",
      sizing: "M",
      dependsOn: ["01-export-endpoint"],
      published: {
        adapter: "github",
        ref: "jharvieux/Harvey#42",
        url: "https://github.com/jharvieux/Harvey/issues/42",
        contentHash: "sha256:9f2c",
      },
    };
    const body = "# Story: Filter\n\nBody text.\n";
    const parsed = parseFrontmatter(serializeFrontmatter(data, body));
    expect(parsed.data).toEqual(data);
    expect(parsed.body).toBe(body);
  });

  it("parses scalars, arrays, and nested objects with typed values", () => {
    const { data } = parseFrontmatter(
      ["---", "sequence: 3", "flag: true", "dependsOn: [a, b]", "empty: []", "---", "body"].join("\n"),
    );
    expect(data.sequence).toBe(3);
    expect(data.flag).toBe(true);
    expect(data.dependsOn).toEqual(["a", "b"]);
    expect(data.empty).toEqual([]);
  });

  it("returns the whole input as body when there is no frontmatter", () => {
    const raw = "# Just a heading\n\nno frontmatter here";
    expect(parseFrontmatter(raw)).toEqual({ data: {}, body: raw });
  });

  it("rejects missing, unterminated, malformed, and duplicate builder frontmatter", () => {
    expect(() => parseFrontmatter("# no frontmatter", { required: true })).toThrow(/frontmatter is required/);
    expect(() => parseFrontmatter("---\ntitle: x", { required: true })).toThrow(/unterminated/);
    expect(() => parseFrontmatter("---\ntitle x\n---\nbody", { required: true })).toThrow(/malformed/);
    expect(() => parseFrontmatter("---\ntitle: first\ntitle: second\n---\nbody", { required: true })).toThrow(/duplicate.*title/);
    expect(() => parseFrontmatter("---\npublished:\n  ref: one\n  ref: two\n---\nbody", { required: true })).toThrow(/duplicate.*published.ref/);
  });

  it("retains contract-valid empty body, empty array, empty optional scalar, and comments", () => {
    expect(parseFrontmatter("---\ndependsOn: []\nnote: \"\"\n# optional comment\n---\n", { required: true }))
      .toEqual({ data: { dependsOn: [], note: "" }, body: "" });
  });

  it("preserves values containing colons and hashes via quoting", () => {
    const data: FrontmatterData = { url: "https://x.test/a#b", ref: "owner/repo#1" };
    const parsed = parseFrontmatter(serializeFrontmatter(data, "x"));
    expect(parsed.data.url).toBe("https://x.test/a#b");
    expect(parsed.data.ref).toBe("owner/repo#1");
  });
});

describe("frontmatter scalar round trips and supported nesting (#2081)", () => {
  it("preserves escaped and typed-looking strings, including array elements", () => {
    const strings = ['Two\nlines', 'Bad\nstatus: accepted', 'Title with "quotes"', 'C:\\notes\\file', 'true', 'false', '1.25', 'a,b', 'a]b', "owner's note", '', '\tindented'];
    for (const value of strings) {
      const data: FrontmatterData = { title: value, dependsOn: [value, 'sibling'], published: { ref: value } };
      expect(parseFrontmatter(serializeFrontmatter(data, "body"), { required: true })).toEqual({ data, body: "body" });
    }
  });

  it.each([
    'published:\n  ref: one\n    url: changed',
    'published:\n    ref: one',
    'published:\n\tref: one',
    'dependsOn: [a,,b]',
    'dependsOn: [[a],b]',
    'title: "unterminated',
  ])("rejects unsupported structure without flattening it: %s", (source) => {
    expect(() => parseFrontmatter(`---\n${source}\n---\nbody`, { required: true })).toThrow(/frontmatter/);
  });
});
