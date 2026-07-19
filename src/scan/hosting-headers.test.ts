import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkHostingConfigHeaders } from "./hosting-headers.js";

describe("checkHostingConfigHeaders", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-hosting-headers-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const write = (rel: string, content: string) => {
    const path = join(dir, rel);
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, content);
  };

  it("returns nothing when no hosting config exists (can't tell)", () => {
    expect(checkHostingConfigHeaders(dir)).toEqual([]);
  });

  it("flags every missing security header in a public/_headers file", () => {
    write("public/_headers", "/*\n  Cache-Control: public, max-age=0\n");
    const taxes = checkHostingConfigHeaders(dir).map((f) => f.title);
    expect(taxes.some((t) => t.includes("Strict-Transport-Security"))).toBe(true);
    expect(taxes.some((t) => t.includes("X-Frame-Options"))).toBe(true);
    expect(taxes.some((t) => t.includes("X-Content-Type-Options"))).toBe(true);
  });

  it("clears a hosting config that sets all three security headers", () => {
    write(
      "public/_headers",
      "/*\n  Strict-Transport-Security: max-age=63072000\n  X-Frame-Options: DENY\n  X-Content-Type-Options: nosniff\n",
    );
    expect(checkHostingConfigHeaders(dir)).toEqual([]);
  });

  it("accepts a CSP frame-ancestors directive in place of X-Frame-Options", () => {
    write(
      "vercel.json",
      JSON.stringify({ headers: [{ source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: "frame-ancestors 'none'" }, { key: "Strict-Transport-Security", value: "max-age=1" }, { key: "X-Content-Type-Options", value: "nosniff" }] }] }),
    );
    expect(checkHostingConfigHeaders(dir).map((f) => f.title)).toEqual([]);
  });

  it("reads headers set across multiple hosting config files (global presence)", () => {
    write("public/_headers", "/*\n  Strict-Transport-Security: max-age=1\n");
    write("netlify.toml", '[[headers]]\n  [headers.values]\n  X-Frame-Options = "DENY"\n  X-Content-Type-Options = "nosniff"\n');
    expect(checkHostingConfigHeaders(dir)).toEqual([]);
  });
});
