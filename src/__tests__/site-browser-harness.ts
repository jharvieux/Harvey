import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser } from "playwright";

const root = fileURLToPath(new URL("../../", import.meta.url));
export interface MailCapture { url: string; method: string; headers: Record<string, string>; body: { to: string[]; attachments?: { filename: string; content: string }[]; [key: string]: unknown } }

/** Real Next pages/API, with the external mail transport denied except for a recorded local stub. */
export async function startSite() {
  const scratch = mkdtempSync(join(tmpdir(), "harvey-site-browser-"));
  const mode = join(scratch, "mode.json");
  const capture = join(scratch, "mail.jsonl");
  const preload = join(scratch, "mail-transport.cjs");
  writeFileSync(mode, "{}");
  writeFileSync(capture, "");
  writeFileSync(preload, `const fs = require('node:fs');
const original = globalThis.fetch;
globalThis.fetch = async function(input, init) {
  const url = String(input?.url ?? input);
  if (url === 'https://api.resend.com/emails') {
    const body = JSON.parse(init.body);
    fs.appendFileSync(${JSON.stringify(capture)}, JSON.stringify({url, method:init.method, headers:Object.fromEntries(new Headers(init.headers)), body})+'\\n');
    const mode = JSON.parse(fs.readFileSync(${JSON.stringify(mode)}, 'utf8'));
    const outcome = body.to.includes('operator@example.invalid') ? mode.operator : mode.requester;
    if (outcome === 'network') throw new TypeError('owned mail transport failure');
    return new Response(JSON.stringify({id:'owned-message'}), {status:outcome || 200, headers:{'content-type':'application/json'}});
  }
  if (/^https?:/.test(url) && !['localhost', '127.0.0.1'].includes(new URL(url).hostname)) throw new Error('External request blocked in owned site test: '+url);
  return original(input, init);
};
`);
  const reservation = createServer();
  await new Promise<void>(resolve => reservation.listen(0, "127.0.0.1", resolve));
  const address = reservation.address();
  if (!address || typeof address === "string") throw new Error("port reservation failed");
  const port = address.port;
  await new Promise<void>(resolve => reservation.close(() => resolve()));
  const origin = `http://127.0.0.1:${port}`;
  // An allowlist prevents a developer's real mail key from entering the Next child.
  const child = spawn(process.execPath, ["--require", preload, join(root, "site/node_modules/next/dist/bin/next"), "dev", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: join(root, "site"), detached: true,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, NEXT_TELEMETRY_DISABLED: "1", NODE_OPTIONS: `--require=${preload}`, RESEND_API_KEY: "owned-fake-mail-key", RESEND_FROM: "Harvey <sender@example.invalid>", SCAN_NOTIFY_TO: "operator@example.invalid" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", chunk => { output += String(chunk); });
  child.stderr.on("data", chunk => { output += String(chunk); });
  let browser: Browser | undefined;
  const stop = async () => {
    await browser?.close();
    if (child.exitCode === null && child.pid) {
      const closed = new Promise<void>(resolve => child.once("close", () => resolve()));
      process.kill(-child.pid, "SIGTERM");
      await closed;
    }
    rmSync(scratch, { recursive: true, force: true });
  };
  try {
    const deadline = Date.now() + 20_000;
    for (;;) {
      if (child.exitCode !== null) throw new Error(`site exited: ${output}`);
      try { if ((await fetch(`${origin}/api/scan`)).ok) break; } catch { /* owned listener not ready */ }
      if (Date.now() > deadline) throw new Error(`site did not start: ${output}`);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    browser = await chromium.launch();
    return {
      origin, browser, stop,
      setMailMode: (value: Record<string, number | string>) => { writeFileSync(mode, JSON.stringify(value)); writeFileSync(capture, ""); },
      mail: (): MailCapture[] => readFileSync(capture, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line) as MailCapture),
      pdf: readFileSync(join(root, "site/public/harvey-sample-report.pdf")),
    };
  } catch (error) { await stop(); throw error; }
}
