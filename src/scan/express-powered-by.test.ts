// #1204 — the static X-Powered-By check. What is under test is where it draws the line (which
// disables clear it) and, just as much, that the bound it cannot see is stated in the finding: the
// operator ruling made the disclosure part of the deliverable, not a comment.

import { describe, expect, it } from "vitest";
import { detectExpressPoweredByFindings } from "./express-powered-by.js";

const scan = (text: string, path = "src/app.ts") => detectExpressPoweredByFindings([{ path, text }]);

describe("detectExpressPoweredByFindings (#1204)", () => {
  it("flags an Express app whose module never disables the header", () => {
    const findings = scan('import express from "express";\nconst app = express();\napp.get("/", (_q, r) => r.send("ok"));\n');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("Low");
    expect(findings[0]!.precisionTier).toBe("review");
    expect(findings[0]!.taxonomy).toContain("version disclosed");
  });

  it("states in the finding what it could not check — the module graph and the edge", () => {
    const evidence = scan('import express from "express";\nconst app = express();\n')[0]!.evidence;
    expect(evidence).toContain("SCOPE OF THIS CHECK");
    expect(evidence).toContain("another module");
    expect(evidence).toMatch(/reverse proxy, CDN or ingress/);
  });

  it.each([
    ['app.disable("x-powered-by");', "the documented disable"],
    ['app.set("x-powered-by", false);', "the set-to-false form"],
    ['app.use((_q, r, n) => { r.removeHeader("X-Powered-By"); n(); });', "a per-response removeHeader"],
    ['app.use((_q, r, n) => { r.setHeader("X-Powered-By", "nginx"); n(); });', "an obfuscating overwrite"],
  ])("clears an app that handles the header: %s (%s)", (line) => {
    expect(scan(`import express from "express";\nconst app = express();\n${line}\n`)).toHaveLength(0);
  });

  it("clears an app that mounts helmet, whose hidePoweredBy default strips it", () => {
    expect(scan('import express from "express";\nimport helmet from "helmet";\nconst app = express();\napp.use(helmet());\n')).toHaveLength(0);
  });

  it("reads the disable out of a require-style app too", () => {
    expect(scan('const express = require("express");\nconst app = express();\napp.disable("x-powered-by");\n', "server.js")).toHaveLength(0);
    expect(scan('const express = require("express");\nconst app = express();\n', "server.js")).toHaveLength(1);
  });

  it("ignores a disable that only appears in a comment — the clear must be real code", () => {
    expect(scan('import express from "express";\n// remember to call app.disable("x-powered-by") here\nconst app = express();\n')).toHaveLength(1);
  });

  it("does not fire on a module that imports express without building an app", () => {
    expect(scan('import express from "express";\nexport const router = express.Router();\n')).toHaveLength(0);
  });

  it("emits one row per module, not one per express() call", () => {
    expect(scan('import express from "express";\nconst a = express();\nconst b = express();\n')).toHaveLength(1);
  });

  it("does not fire on an unrelated zero-argument factory called `app`", () => {
    expect(scan('import fastify from "fastify";\nconst app = fastify();\n')).toHaveLength(0);
  });
});
