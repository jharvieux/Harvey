import { describe, expect, it } from "vitest";
import { detectEmitterUnhandledErrorFindings } from "./emitter-error.js";

// #1202 — OWASP Node.js Security CS, Error & Exception Handling: an EventEmitter emitting
// 'error' with no listener crashes the process. Same-file heuristic only (disclosed in the
// finding's evidence/fix); each test below documents exactly what that blind spot means.

describe("emitter-error (#1202 — EventEmitter emits 'error' with no same-file listener)", () => {
  it("flags an emitter with no same-file error listener", () => {
    const text = `import { EventEmitter } from "node:events";
export const jobs = new EventEmitter();
jobs.on("done", (id) => console.log(id));
export function startJob(id) {
  setTimeout(() => jobs.emit("error", new Error("boom")), 10);
}
`;
    const findings = detectEmitterUnhandledErrorFindings([{ path: "src/jobs.ts", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "High", precisionTier: "review", confidence: "Review" });
    expect(findings[0]?.taxonomy).toBe("EventEmitter emits 'error' with no registered listener");
  });

  it("stays silent when a same-file .on(\"error\", ...) listener is registered", () => {
    const text = `import { EventEmitter } from "node:events";
export const jobs = new EventEmitter();
jobs.on("error", (err) => console.error(err));
export function startJob(id) {
  setTimeout(() => jobs.emit("error", new Error("boom")), 10);
}
`;
    expect(detectEmitterUnhandledErrorFindings([{ path: "src/jobs.ts", text }])).toHaveLength(0);
  });

  it("stays silent when a same-file .once(\"error\", ...) listener is registered", () => {
    const text = `import { EventEmitter } from "node:events";
export const jobs = new EventEmitter();
jobs.once("error", (err) => console.error(err));
export function startJob(id) {
  jobs.emit("error", new Error("boom"));
}
`;
    expect(detectEmitterUnhandledErrorFindings([{ path: "src/jobs.ts", text }])).toHaveLength(0);
  });

  it("stays silent when there is no 'error' emit at all", () => {
    const text = `import { EventEmitter } from "node:events";
export const jobs = new EventEmitter();
jobs.on("done", (id) => console.log(id));
export function finish(id) {
  jobs.emit("done", id);
}
`;
    expect(detectEmitterUnhandledErrorFindings([{ path: "src/jobs.ts", text }])).toHaveLength(0);
  });

  it("DISCLOSED same-file-only limitation: a listener attached in an IMPORTING module is invisible, so this still fires", () => {
    // Documents the exact blind spot recorded in owasp-nodejs.entries.ts's P-OWASP-NODE-EMITTER-ERROR
    // note — proving no listener exists ANYWHERE needs cross-file reasoning this pass does not do.
    const text = `import { EventEmitter } from "node:events";
export const jobs = new EventEmitter();
export function startJob(id) {
  jobs.emit("error", new Error("boom"));
}
`;
    const findings = detectEmitterUnhandledErrorFindings([{ path: "src/jobs.ts", text }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("no `jobs.on(\"error\", ...)`");
  });
});
