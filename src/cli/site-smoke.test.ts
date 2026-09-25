import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../", import.meta.url));
const paths = [...readFileSync(new URL("../../site/app/sitemap.ts", import.meta.url), "utf8").matchAll(/path:\s*"([^"]+)"/g)].map(match => match[1]!);

async function smoke(mode: "healthy" | "wrong" | "missing" | "loop" | "dead" | "not-redirect" | "not-modified") {
  const requests: { method: string; path: string }[] = [];
  const server = createServer((request, response) => {
    const path = request.url ?? "/";
    requests.push({ method: request.method ?? "GET", path });
    if (path === "/sitemap.xml") { response.end(`<urlset>${paths.map(route => `<url><loc>http://local.invalid${route}</loc></url>`).join("")}</urlset>`); return; }
    if (path === "/api/scan") {
      if (request.method === "POST") { response.writeHead(400); response.end("invalid fixture input"); }
      else { response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ configured: true, sandboxSender: false })); }
      return;
    }
    if (path === "/intake") {
      response.statusCode = mode === "not-redirect" ? 200 : mode === "not-modified" ? 304 : 307;
      if (mode !== "missing") response.setHeader("location", mode === "wrong" ? "/wrong" : "/#scan");
      response.end(); return;
    }
    if (path === "/" && mode === "loop") { response.writeHead(302, { location: "/intake" }); response.end(); return; }
    response.statusCode = path === "/" && mode === "dead" ? 404 : 200;
    response.end("owned fixture");
  });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("owned server did not bind");
    const result = await new Promise<{ code: number; output: string }>((done, reject) => {
      const child = spawn(process.execPath, ["--import", "tsx", "src/cli/site-smoke.ts", "--base", `http://127.0.0.1:${address.port}`], { cwd: root, stdio: ["ignore", "pipe", "pipe"], timeout: 10_000 });
      let output = "";
      child.stdout.on("data", chunk => { output += String(chunk); });
      child.stderr.on("data", chunk => { output += String(chunk); });
      child.once("error", reject);
      child.once("close", code => done({ code: code ?? 1, output }));
    });
    return { ...result, requests };
  } finally {
    await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
  }
}

describe("shipping site smoke redirect destination contract", () => {
  it("accepts the declared healthy destination and actually probes it", async () => {
    const result = await smoke("healthy");
    expect(result.code, result.output).toBe(0);
    expect(result.requests.filter(request => request.path === "/intake")).toEqual([{ method: "GET", path: "/intake" }]);
    expect(result.requests.filter(request => request.path === "/")).toHaveLength(2);
    expect(result.output).toContain("/#scan");
  });
  it.each(["wrong", "missing", "loop", "dead", "not-redirect", "not-modified"] as const)("rejects %s while naming the source and intended destination", async mode => {
    const result = await smoke(mode);
    expect(result.code, result.output).toBe(1);
    expect(result.output).toMatch(/FAIL\s+declared redirects/);
    expect(result.output).toContain("/intake");
    expect(result.output).toContain("/#scan");
    expect(result.requests.some(request => request.path === "/wrong")).toBe(false);
    expect(result.requests.filter(request => request.path === "/intake").length).toBeLessThanOrEqual(1);
  });
});
