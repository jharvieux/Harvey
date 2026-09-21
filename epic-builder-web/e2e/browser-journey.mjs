// A bounded Chrome journey against the actual Next server. Uses the built-in scaffold model,
// dry-run tracker and an isolated filesystem partition; no account or external service is used.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const appDir = resolve(import.meta.dirname, "..");
const chrome = process.env.CHROME_BIN ?? (
  process.platform === "darwin"
    ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    : "/usr/bin/chromium"
);

async function freePort() {
  const server = createServer();
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const port = server.address().port;
  await new Promise((done) => server.close(done));
  return port;
}

async function until(label, check, limitMs = 90_000) {
  const start = Date.now();
  let lastError;
  while (Date.now() - start < limitMs) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw new Error("Timed out waiting for " + label + (lastError ? ": " + lastError.message : ""));
}

class Cdp {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.nextId = 0;
    this.pending = new Map();
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (!message.id) return;
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
    });
  }

  async ready() {
    await new Promise((resolveReady, rejectReady) => {
      if (this.socket.readyState === WebSocket.OPEN) return resolveReady();
      this.socket.addEventListener("open", resolveReady, { once: true });
      this.socket.addEventListener("error", rejectReady, { once: true });
    });
  }

  send(method, params = {}) {
    const id = ++this.nextId;
    return new Promise((resolveReply, rejectReply) => {
      this.pending.set(id, { resolve: resolveReply, reject: rejectReply });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async eval(expression) {
    const reply = await this.send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true,
    });
    if (reply.exceptionDetails) throw new Error(reply.exceptionDetails.text);
    return reply.result.value;
  }

  close() {
    this.socket.close();
  }
}

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((done) => child.once("exit", done)),
    delay(5000).then(() => child.kill("SIGKILL")),
  ]);
}

async function main() {
  assert.ok(existsSync(chrome), "Chrome binary is required: " + chrome);
  const dataDir = mkdtempSync(join(tmpdir(), "epic-browser-data-"));
  const chromeDir = mkdtempSync(join(tmpdir(), "epic-browser-chrome-"));
  const port = await freePort();
  const origin = "http://127.0.0.1:" + port;
  const logs = [];
  let server;
  let browser;
  let cdp;
  try {
    server = spawn(process.execPath, [join(appDir, "node_modules/next/dist/bin/next"), "dev", "-H", "127.0.0.1", "-p", String(port)], {
      cwd: appDir,
      env: {
        ...process.env,
        EPIC_BUILDER_AUTH: "shared",
        EPIC_BUILDER_PASSWORD: "browser-fixture-password",
        EPIC_BUILDER_SESSION_SECRET: "browser-fixture-signing-key",
        EPIC_BUILDER_STORAGE: "filesystem",
        EPIC_BUILDER_MODEL: "scaffold",
        EPIC_BUILDER_DATA_DIR: dataDir,
        GITHUB_TOKEN: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    for (const stream of [server.stdout, server.stderr]) {
      stream.on("data", (chunk) => logs.push(String(chunk)));
    }
    await until("Next server", async () => {
      if (server.exitCode !== null) throw new Error("Next exited: " + logs.join("").slice(-2000));
      return fetch(origin + "/login").then((response) => response.ok).catch(() => false);
    });

    browser = spawn(chrome, [
      "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-gpu",
      "--no-sandbox", "--remote-debugging-port=0", "--user-data-dir=" + chromeDir, "about:blank",
    ], { stdio: ["ignore", "pipe", "pipe"] });
    const active = join(chromeDir, "DevToolsActivePort");
    await until("Chrome DevTools port", () => existsSync(active));
    const debugPort = Number(readFileSync(active, "utf8").split("\n")[0]);
    const targets = await fetch("http://127.0.0.1:" + debugPort + "/json/list").then((response) => response.json());
    const target = targets.find((item) => item.type === "page");
    assert.ok(target, "Chrome did not create a page target");
    cdp = new Cdp(target.webSocketDebuggerUrl);
    await cdp.ready();
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: `
      window.__epicHttp = [];
      const originalFetch = window.fetch.bind(window);
      window.fetch = async (...args) => {
        const response = await originalFetch(...args);
        const url = String(args[0]);
        if (url.startsWith("/api/")) {
          let payload = null;
          try { payload = await response.clone().json(); } catch {}
          window.__epicHttp.push({ url, status: response.status, payload });
        }
        return response;
      };
    ` });
    await cdp.send("Page.navigate", { url: origin + "/" });
    await until("hydrated login form", () => cdp.eval("location.pathname === '/login' && Object.keys(document.querySelector('form') ?? {}).some(k => k.startsWith('__reactFiber$'))"));
    await cdp.eval(`(() => {
      const input = document.querySelector("#pw");
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(input, "browser-fixture-password");
      input.dispatchEvent(new Event("input", { bubbles: true }));
      document.querySelector("button[type=submit]").click();
    })()`);
    await until("authenticated wizard", () => cdp.eval("location.pathname === '/' && !!document.querySelector('#prompt')"));
    await cdp.eval(`(() => {
      const input = document.querySelector("#prompt");
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(input, "Local browser proof for durable epic workflow");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    })()`);
    await until("enabled Start button", () => cdp.eval("Array.from(document.querySelectorAll('button')).some(b => b.textContent.trim() === 'Start' && !b.disabled)"));
    const click = async (label) => {
      const found = await cdp.eval("(() => { const b = Array.from(document.querySelectorAll('button')).find(x => x.textContent.trim() === " + JSON.stringify(label) + "); if (!b || b.disabled) return false; b.click(); return true; })()");
      assert.equal(found, true, "Missing enabled button: " + label);
    };
    await click("Start");
    await until("clarifying questions", () => cdp.eval("document.body.innerText.includes('Clarifying questions')"));
    await click("Draft the epic");
    await until("epic review", () => cdp.eval("document.body.innerText.includes('Review: epic.md')"));
    await click("Accept");
    await until("story fan-out", () => cdp.eval("document.body.innerText.includes('Story fan-out')"));
    await click("Preview proposed stories");
    await until("manifest", () => cdp.eval("Array.from(document.querySelectorAll('button')).some(b => b.textContent.trim() === 'Draft these stories')"));
    await click("Draft these stories");
    await until("story review", () => cdp.eval("document.body.innerText.includes('stories-review')"));
    let accepted = 0;
    while (await cdp.eval("document.body.innerText.includes('stories-review')")) {
      assert.ok(accepted++ < 10, "Unbounded story review loop");
      await click("Accept");
      await until("story review transition", () => cdp.eval("!document.querySelector('button')?.disabled"));
    }
    await until("publish step", () => cdp.eval("Array.from(document.querySelectorAll('button')).some(b => b.textContent.trim() === 'Dry run')"));
    await click("Dry run");
    await until("dry-run summary", () => cdp.eval("!!document.querySelector('pre.summary')"));

    const http = await cdp.eval("window.__epicHttp");
    const path = (name) => http.filter((item) => item.url.startsWith("/api/" + name));
    for (const name of ["login", "session", "clarify", "review", "fanout", "publish"]) {
      assert.ok(path(name).some((item) => item.status === 200), "Missing successful HTTP response: " + name);
    }
    const slug = path("session").find((item) => item.payload?.slug)?.payload.slug;
    assert.ok(slug, "Session response did not carry a slug");
    assert.ok(path("publish").some((item) => item.payload?.dryRun === true && item.payload.created >= 1));
    const saved = JSON.parse(readFileSync(join(dataDir, "operator", ".epic-builder", slug, "session.json"), "utf8"));
    assert.equal(saved.slug, slug);
    assert.equal(saved.state, "publish");
    assert.equal(saved.publish.attempts, 1);
    assert.ok(saved.stories.length >= 1);
    assert.ok(saved.stories.every((story) => story.status === "accepted"));
    console.log(JSON.stringify({
      browser: "Chrome headless", routeResponses: http.filter((item) => item.url.startsWith("/api/")).map((item) => ({ url: item.url, status: item.status })),
      slug, state: saved.state, stories: saved.stories.length, dryRunAttempts: saved.publish.attempts,
    }));
  } catch (error) {
    console.error(logs.join("").slice(-3000));
    if (cdp) {
      try {
        console.error("Browser state:", await cdp.eval("JSON.stringify({ url: location.href, text: document.body?.innerText?.slice(0, 1500), http: window.__epicHttp })"));
      } catch {}
    }
    throw error;
  } finally {
    cdp?.close();
    await stop(browser);
    await stop(server);
    rmSync(chromeDir, { recursive: true, force: true });
    rmSync(dataDir, { recursive: true, force: true });
  }
}

await main();
