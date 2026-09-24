import { spawn } from "node:child_process";
import { clearTimeout, setTimeout } from "node:timers";
import { fileURLToPath, URL } from "node:url";

async function boundedWait(promises, ms) {
  let timer;
  try {
    await Promise.race([
      ...promises,
      new Promise((resolve) => { timer = setTimeout(resolve, ms); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export class ValidationWorker {
  #child;
  #closed;
  #isClosed = false;
  #error;
  #stderr = "";
  #request;
  #nextId = 0;

  constructor(root) {
    this.#child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("./worker.mjs", import.meta.url))], {
      cwd: root,
      stdio: ["ignore", "ignore", "pipe", "ipc"],
    });
    this.#child.stderr.setEncoding("utf8");
    this.#child.stderr.on("data", (chunk) => { this.#stderr += chunk; });
    this.#child.once("error", (error) => { this.#error = error; });
    this.#closed = new Promise((resolve) => {
      this.#child.once("close", (code, signal) => {
        this.#isClosed = true;
        this.#error ??= new Error(`validation worker exited ${code ?? signal}: ${this.#stderr}`);
        resolve();
      });
    });
    this.#child.on("message", (result) => {
      const request = this.#request;
      if (!request || result.id !== request.id || request.result) {
        this.#error = new Error("validation worker returned an unexpected response");
      } else if (result.error) {
        this.#error = new Error(result.error);
      } else if (result.pid !== this.#child.pid || !Array.isArray(result.problems)
        || result.problems.some((problem) => typeof problem !== "string")
        || !Number.isFinite(result.elapsedMs) || result.elapsedMs < 0) {
        this.#error = new Error("validation worker returned an invalid response");
      } else {
        request.result = result;
      }
      request?.resolve();
    });
  }

  get pid() { return this.#child.pid; }

  start(input) {
    if (this.#error) throw this.#error;
    if (this.#request && !this.#request.result) throw new Error("validation worker already has an unfinished request");
    let resolve;
    const request = {
      id: ++this.#nextId,
      completed: new Promise((done) => { resolve = done; }),
      resolve,
      result: undefined,
    };
    this.#request = request;
    this.#child.send({ ...input, id: request.id }, (error) => {
      if (error) {
        this.#error = error;
        request.resolve();
      }
    });
    return request;
  }

  async waitSlice(request, ms = 10_000) {
    await boundedWait([request.completed, this.#closed], ms);
    if (this.#error) throw this.#error;
  }

  async finish(request) {
    if (this.#error) throw this.#error;
    if (!request.result) {
      await this.stop();
      throw new Error("source validation exceeded its bounded wait budget");
    }
    return request.result;
  }

  async validate(input) {
    const request = this.start(input);
    // Warm requests and the bounded cache-invalidation fixtures retain a limit
    // below Vitest's existing timeout, including terminate-and-reap cleanup.
    await this.waitSlice(request, 20_000);
    return (await this.finish(request)).problems;
  }

  async stop() {
    if (this.#isClosed) return;
    this.#child.kill("SIGTERM");
    await boundedWait([this.#closed], 2_000);
    if (this.#isClosed) return;
    this.#child.kill("SIGKILL");
    await boundedWait([this.#closed], 5_000);
    if (!this.#isClosed) throw new Error(`failed to reap validation worker ${this.#child.pid}`);
  }
}
