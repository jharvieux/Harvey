import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it } from "vitest";
import { createWorkspace, writeDraft, readDraft, writeFile, saveSession, loadSession } from "../epic-builder/workspace.js";

it("keeps the actual publish CLI pending until recovered story effects finish (#2113)", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "epic-publish-cli-"));
  const { dir, slug, session } = createWorkspace(cwd, "Publisher recovery control");
  writeDraft(dir, "epic.md", { data: { kind: "epic", title: "Control epic", status: "accepted" }, body: "# Epic\n" });
  writeDraft(dir, "stories/01-story.md", { data: { kind: "story", sequence: 1, title: "Control story", status: "accepted", sizing: "M", dependsOn: [] }, body: "# Story\n" });
  writeFile(dir, "briefs/01-story.brief.md", "# Implementation brief\n");
  session.state = "publish";
  session.stories = [{ file: "stories/01-story.md", status: "accepted", revisions: 0 }];
  saveSession(dir, session);
  const issues = new Map<number, { number: number; html_url: string; repository_url: string; body: string; labels: string[] }>();
  let failed = false;
  let attachments = 0;
  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, "http://fixture.invalid");
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    const method = req.method ?? "GET";
    const send = (data: unknown, status = 200) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(data)); };
    if (url.pathname === "/search/issues") {
      const marker = url.searchParams.get("q")?.match(/<!-- .*? -->/)?.[0] ?? "";
      const items = [...issues.values()].filter(issue => issue.body.includes(marker));
      send({ items, total_count: items.length, incomplete_results: false }); return;
    }
    if (url.pathname === "/repos/fixture/repo/issues" && method === "POST") {
      const id = issues.size + 1;
      const issue = { number: id, html_url: `https://github.com/fixture/repo/issues/${id}`, repository_url: "https://api.github.com/repos/fixture/repo", body: body.body as string, labels: [] as string[] };
      issues.set(id, issue); send(issue); return;
    }
    if (url.pathname.includes("/contents/") && method === "PUT") {
      attachments++; send({ content: { html_url: "https://github.com/fixture/repo/blob/main/brief.md" } }); return;
    }
    const match = url.pathname.match(/^\/repos\/fixture\/repo\/issues\/(\d+)(\/labels)?$/);
    if (!match) { send({ error: "Unexpected fixture request" }, 500); return; }
    const id = Number(match[1]);
    const issue = issues.get(id)!;
    if (method === "GET") { send(issue); return; }
    if (!failed && method === "PATCH" && id === 1) { failed = true; send({ error: "Controlled link failure" }, 500); return; }
    if (match[2]) issue.labels = body.labels;
    else Object.assign(issue, body);
    send(issue);
  });
  try {
    await new Promise<void>((done, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", done); });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Missing fixture server address");
    const shim = join(cwd, "fixture-fetch.mjs");
    writeFileSync(shim, `const fetchOwned = globalThis.fetch; globalThis.fetch = (input, init) => { const url = new URL(String(input)); if (url.origin !== 'https://api.github.com') throw new Error('External transport forbidden'); return fetchOwned(process.env.PUBLISH_FIXTURE_ORIGIN + url.pathname + url.search, init); };`);
    const run = () => new Promise<{ code: number | null; stderr: string }>((done, reject) => {
      const child = spawn(process.execPath, ["--import", resolve("node_modules/tsx/dist/loader.mjs"), "--import", shim, resolve("src/cli/epic.ts"), "publish", slug], {
        cwd,
        env: { ...process.env, GITHUB_TOKEN: "publisher-fixture-token", GITHUB_OWNER: "fixture", GITHUB_REPO: "repo", PUBLISH_FIXTURE_ORIGIN: `http://127.0.0.1:${address.port}` },
        stdio: ["ignore", "ignore", "pipe"],
        timeout: 20_000,
      });
      let stderr = "";
      child.stderr.on("data", value => { stderr += String(value); });
      child.once("error", reject);
      child.once("close", code => done({ code, stderr }));
    });
    const first = await run();
    expect(first.code, first.stderr).toBe(1);
    expect(loadSession(dir)?.state).toBe("publish");
    expect(issues.size).toBe(2);
    expect(readDraft(dir, "stories/01-story.md").data.published).toMatchObject({ ref: "2" });
    expect(readDraft(dir, "stories/01-story.md").data.publication).toMatchObject({ state: "pending" });
    for (const issue of issues.values()) issue.body += "\nClient annotation";
    const second = await run();
    expect(second.code, second.stderr).toBe(0);
    expect(loadSession(dir)?.state).toBe("done");
    expect(issues.size).toBe(2);
    expect(issues.get(1)?.body).toContain("- [ ] #2 ");
    expect(issues.get(2)?.labels).toEqual(["story", "size:M"]);
    expect(issues.get(2)?.body).toContain("Client annotation");
    expect(issues.get(2)?.body).toContain("📄 Implementation brief:");
    expect(readDraft(dir, "stories/01-story.md").data.brief).toContain("/brief.md");
    expect(attachments).toBe(1);
  } finally {
    await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
    rmSync(cwd, { recursive: true, force: true });
  }
});
