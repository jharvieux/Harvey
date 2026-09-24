import { copyFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ValidationWorker as Worker } from "./__fixtures__/effectiveness-delivery/validation-worker.mjs";

const owned: { directory: string; worker: Worker }[] = [];

async function controlledWorker(action: string, initialError = false) {
  const directory = mkdtempSync(join(tmpdir(), "harvey-validation-late-exit-"));
  const trigger = join(directory, "trigger");
  copyFileSync(new URL("./__fixtures__/effectiveness-delivery/validation-worker.mjs", import.meta.url), join(directory, "validation-worker.mjs"));
  writeFileSync(join(directory, "worker.mjs"), `
    import { existsSync } from "node:fs";
    process.on("message", request => {
      process.send(${initialError ? '{ id: request.id, error: "planted validator failure" }' : '{ id: request.id, pid: process.pid, problems: [], elapsedMs: 1 }'});
      const timer = setInterval(() => {
        if (!existsSync(${JSON.stringify(trigger)})) return;
        clearInterval(timer);
        ${action}
      }, 5);
    });
    process.on("disconnect", () => process.exit(0));
  `);
  const module = await import(pathToFileURL(join(directory, "validation-worker.mjs")).href) as { ValidationWorker: typeof Worker };
  const worker = new module.ValidationWorker(process.cwd());
  owned.push({ directory, worker });
  return { worker, trigger };
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function observeExit(pid: number): Promise<void> {
  const deadline = performance.now() + 2_000;
  while (alive(pid) && performance.now() < deadline) await delay(5);
  expect(alive(pid)).toBe(false);
  // Let the already-exited child's close event reach the managed client.
  await new Promise<void>((resolve) => setImmediate(resolve));
}

afterEach(async () => {
  for (const { directory, worker } of owned.splice(0)) {
    await worker.stop().catch(() => undefined);
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("validation worker final-response teardown", () => {
  it.each([
    ["zero exit", "process.exit(0);"],
    ["nonzero exit", "process.exit(7);"],
    ["signal exit", 'process.kill(process.pid, "SIGKILL");'],
  ])("surfaces a late unexpected %s after a completed response", async (_name, action) => {
    const { worker, trigger } = await controlledWorker(action);
    await expect(worker.validate({ kind: "inventory", inventory: {} as never })).resolves.toEqual([]);
    writeFileSync(trigger, "exit after the observed response");
    await observeExit(worker.pid!);
    await expect(worker.stop()).rejects.toThrow("validation worker exited");
  });

  it("surfaces a late protocol error even after the child closes", async () => {
    const { worker, trigger } = await controlledWorker('process.send({ id: request.id + 1 }, () => process.exit(0));');
    await expect(worker.validate({ kind: "inventory", inventory: {} as never })).resolves.toEqual([]);
    writeFileSync(trigger, "send the late invalid response");
    await observeExit(worker.pid!);
    await expect(worker.stop()).rejects.toThrow("unexpected response");
  });

  it("allows requested teardown and repeated cleanup after a valid response", async () => {
    const { worker, trigger } = await controlledWorker("process.exit(0);");
    await expect(worker.validate({ kind: "inventory", inventory: {} as never })).resolves.toEqual([]);
    expect(existsSync(trigger)).toBe(false);
    await expect(worker.stop()).resolves.toBeUndefined();
    expect(alive(worker.pid!)).toBe(false);
    await expect(worker.stop()).resolves.toBeUndefined();
  });

  it("reaps after an already observed validator error without hiding a second assertion", async () => {
    const { worker } = await controlledWorker("process.exit(0);", true);
    await expect(worker.validate({ kind: "inventory", inventory: {} as never })).rejects.toThrow("planted validator failure");
    await expect(worker.stop()).resolves.toBeUndefined();
    expect(alive(worker.pid!)).toBe(false);
  });
});
