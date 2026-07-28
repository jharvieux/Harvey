import { describe, expect, it } from "vitest";
import { detectExpressSecurityHeaderFindings } from "./express-security-headers.js";

const run = (text: string) => detectExpressSecurityHeaderFindings([{ path: "src/server.ts", text }]);

const BARE = `import express from "express";
const app = express();
app.get("/healthz", (_req, res) => res.send("ok"));
export default app;
`;

describe("detectExpressSecurityHeaderFindings (#1350, the effect check #1204's decline assumed existed)", () => {
  it("flags an Express app that sets none of the four security headers", () => {
    const findings = run(BARE);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toBe("Express app sets no security response headers");
    expect(findings[0]!.precisionTier).toBe("review");
  });

  // The load-bearing one. #1204's ruling is that library ADOPTION is not a defect, so an app that
  // sets the headers by hand must clear — otherwise this rule is the false positive on correct code
  // the ruling exists to prevent, and it would fire on the by-design fixture and fail the gate.
  it("clears an app that sets the headers by hand with no middleware at all", () => {
    expect(
      run(`import express from "express";
const app = express();
app.use((_req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=63072000");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});
export default app;
`),
    ).toEqual([]);
  });

  it("clears an app that mounts helmet", () => {
    expect(
      run(`import express from "express";
import helmet from "helmet";
const app = express();
app.use(helmet());
export default app;
`),
    ).toEqual([]);
  });

  // A CSP frame-ancestors directive substitutes for X-Frame-Options, so any CSP means the response
  // headers were considered. Without this the rule would flag an app with a deliberate CSP-only
  // posture, which is a false positive on a stricter configuration than the one it recommends.
  it("clears an app whose only header is a Content-Security-Policy", () => {
    expect(
      run(`import express from "express";
const app = express();
app.use((_req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
  next();
});
export default app;
`),
    ).toEqual([]);
  });

  // Scope control: the rule keys on an Express app being CONSTRUCTED here, not on the import. A
  // module that only mounts a Router onto someone else's app has no header posture to be missing.
  it("stays silent on a module that imports express but constructs no app", () => {
    expect(
      run(`import express from "express";
const router = express.Router();
router.get("/x", (_req, res) => res.send("ok"));
export default router;
`),
    ).toEqual([]);
  });

  it("stays silent on a module with no express involvement", () => {
    expect(run(`export const add = (a: number, b: number) => a + b;\n`)).toEqual([]);
  });

  // The bound this pass cannot see has to be in the finding a client reads, not only in the source
  // comment — the #1204/#1332 rule that a recorded bound must reach the finding it bounds.
  it("states its same-module scope and the proxy/CDN caveat in the emitted evidence", () => {
    const evidence = run(BARE)[0]!.evidence;
    expect(evidence).toContain("reads the module that CONSTRUCTS the app and nothing else");
    expect(evidence).toContain("reverse proxy, CDN or ingress");
  });

  // The decline this detector exists to make true: it must never read as "you did not import
  // helmet". If the evidence ever names the package as the requirement, the false-positive-on-
  // correct-code failure #1204 ruled against is back.
  it("does not present the finding as a missing helmet dependency", () => {
    expect(run(BARE)[0]!.evidence).not.toContain("helmet");
  });
});
