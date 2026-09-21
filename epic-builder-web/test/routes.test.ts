import { readdirSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveUserId } from "../lib/auth.js";
import { productionDeps } from "../lib/deps.js";
import * as core from "../lib/core.js";
import * as session from "../app/api/session/route.js";
import * as clarify from "../app/api/clarify/route.js";
import * as review from "../app/api/review/route.js";
import * as fanout from "../app/api/fanout/route.js";
import * as publish from "../app/api/publish/route.js";

vi.mock("../lib/auth.js", () => ({ resolveUserId: vi.fn() }));
vi.mock("../lib/deps.js", () => ({ productionDeps: vi.fn() }));
vi.mock("../lib/core.js", () => ({
  startSession: vi.fn(), getState: vi.fn(), submitClarify: vi.fn(), reviewAction: vi.fn(),
  previewManifest: vi.fn(), fanOut: vi.fn(), runPublish: vi.fn(),
}));

type Handler = (req: Request) => Promise<Response>;
const handlers: { name: string; run: Handler; url: string; body?: unknown; core: keyof typeof core }[] = [
  { name: "session POST", run: session.POST, url: "http://localhost/api/session", body: { prompt: "An epic" }, core: "startSession" },
  { name: "session GET", run: session.GET, url: "http://localhost/api/session?slug=a", core: "getState" },
  { name: "clarify POST", run: clarify.POST, url: "http://localhost/api/clarify", body: { slug: "a", answers: "yes" }, core: "submitClarify" },
  { name: "review POST", run: review.POST, url: "http://localhost/api/review", body: { slug: "a", action: "accept", target: "epic.md" }, core: "reviewAction" },
  { name: "fanout GET", run: fanout.GET, url: "http://localhost/api/fanout?slug=a", core: "previewManifest" },
  { name: "fanout POST", run: fanout.POST, url: "http://localhost/api/fanout", body: { slug: "a", keep: [0] }, core: "fanOut" },
  { name: "publish POST", run: publish.POST, url: "http://localhost/api/publish", body: { slug: "a", dryRun: true }, core: "runPublish" },
];
const coreFns = [
  core.startSession, core.getState, core.submitClarify, core.reviewAction,
  core.previewManifest, core.fanOut, core.runPublish,
];
const commit = vi.fn<() => Promise<void>>();
const release = vi.fn<() => Promise<void>>();
const deps = { cwd: "/fixture/user-a", model: {}, templates: {}, makeTracker: vi.fn() } as unknown as core.CoreDeps;

function request(h: (typeof handlers)[number], body: unknown = h.body): Request {
  return new Request(h.url, h.body === undefined ? undefined : {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(resolveUserId).mockResolvedValue("user-a");
  vi.mocked(productionDeps).mockResolvedValue({ deps, commit, release });
  commit.mockResolvedValue();
  release.mockResolvedValue();
  for (const fn of coreFns) vi.mocked(fn).mockResolvedValue({ ok: true, state: "epic-review" } as never);
});
afterEach(() => vi.clearAllMocks());

describe("all current authenticated HTTP handlers", () => {
  it("discovers the complete route set, including login", () => {
    const directories = readdirSync(new URL("../app/api/", import.meta.url), { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && readdirSync(new URL("../app/api/" + entry.name + "/", import.meta.url)).includes("route.ts"))
      .map((entry) => entry.name).sort();
    expect(directories).toEqual(["clarify", "fanout", "login", "publish", "review", "session"]);
    expect(handlers.map((h) => h.name)).toHaveLength(7);
  });

  it.each(handlers)("$name denies before invoking core, dependencies or writes", async (h) => {
    vi.mocked(resolveUserId).mockResolvedValue(null);
    const res = await h.run(request(h));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(productionDeps).not.toHaveBeenCalled();
    expect(coreFns.every((fn) => vi.mocked(fn).mock.calls.length === 0)).toBe(true);
    expect(commit).not.toHaveBeenCalled();
  });

  it.each(handlers)("$name uses the verified partition, returns JSON and commits exactly once", async (h) => {
    const res = await h.run(request(h));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(h.core === "previewManifest" ? { entries: { ok: true, state: "epic-review" } } : { ok: true, state: "epic-review" });
    expect(productionDeps).toHaveBeenCalledExactlyOnceWith("user-a");
    expect(vi.mocked(core[h.core])).toHaveBeenCalledTimes(1);
    expect(vi.mocked(core[h.core]).mock.calls[0]![0]).toBe(deps);
    expect(commit).toHaveBeenCalledTimes(1);
    expect(release).toHaveBeenCalledTimes(1);
  });

  it.each(handlers)("$name returns a core failure without committing and releases resources", async (h) => {
    vi.mocked(core[h.core]).mockRejectedValueOnce(new Error("controlled core failure"));
    const res = await h.run(request(h));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "controlled core failure" });
    expect(commit).not.toHaveBeenCalled();
    expect(release).toHaveBeenCalledTimes(1);
  });

  it.each(handlers)("$name catches dependency acquisition failure before core work", async (h) => {
    vi.mocked(productionDeps).mockRejectedValueOnce(new Error("hydrate failed"));
    const res = await h.run(request(h));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "hydrate failed" });
    expect(coreFns.every((fn) => vi.mocked(fn).mock.calls.length === 0)).toBe(true);
    expect(commit).not.toHaveBeenCalled();
  });

  it.each(handlers.filter((h) => h.body !== undefined))("$name catches malformed JSON after authentication", async (h) => {
    const res = await h.run(new Request(h.url, { method: "POST", body: "{" }));
    expect(res.status).toBe(400);
    expect(coreFns.every((fn) => vi.mocked(fn).mock.calls.length === 0)).toBe(true);
    expect(commit).not.toHaveBeenCalled();
    expect(release).toHaveBeenCalledTimes(1);
  });

  it.each(handlers.filter((h) => h.body !== undefined))("$name rejects missing required fields without committing", async (h) => {
    const res = await h.run(request(h, {}));
    expect(res.status).toBe(400);
    expect(coreFns.every((fn) => vi.mocked(fn).mock.calls.length === 0)).toBe(true);
    expect(commit).not.toHaveBeenCalled();
    expect(release).toHaveBeenCalledTimes(1);
  });

  it("keeps the handler error when release also fails", async () => {
    vi.mocked(core.startSession).mockRejectedValueOnce(new Error("handler failed"));
    release.mockRejectedValueOnce(new Error("release failed"));
    const res = await session.POST(request(handlers[0]!));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "handler failed" });
  });

  it("returns a commit or release failure and still attempts one release", async () => {
    commit.mockRejectedValueOnce(new Error("flush failed"));
    const flush = await session.POST(request(handlers[0]!));
    expect(flush.status).toBe(400);
    expect(await flush.json()).toEqual({ error: "flush failed" });
    expect(release).toHaveBeenCalledTimes(1);

    vi.clearAllMocks();
    vi.mocked(resolveUserId).mockResolvedValue("user-a");
    vi.mocked(productionDeps).mockResolvedValue({ deps, commit, release });
    vi.mocked(core.startSession).mockResolvedValue({ ok: true } as never);
    commit.mockResolvedValue();
    release.mockRejectedValueOnce(new Error("release failed"));
    const cleanup = await session.POST(request(handlers[0]!));
    expect(cleanup.status).toBe(400);
    expect(await cleanup.json()).toEqual({ error: "release failed" });
  });
});
