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

  it("preserves values containing colons and hashes via quoting", () => {
    const data: FrontmatterData = { url: "https://x.test/a#b", ref: "owner/repo#1" };
    const parsed = parseFrontmatter(serializeFrontmatter(data, "x"));
    expect(parsed.data.url).toBe("https://x.test/a#b");
    expect(parsed.data.ref).toBe("owner/repo#1");
  });
});
