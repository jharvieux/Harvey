import { EventEmitter } from "node:events";

// N-EMITTER-ERROR-HANDLED (negative for P-OWASP-NODE-EMITTER-ERROR): same emit shape as
// unhandled-rejection.ts, but a same-file `.on("error", ...)` listener is registered on the same
// emitter, so it must stay silent.
export const jobs = new EventEmitter();

jobs.on("done", (id: string) => {
  console.log(`job ${id} finished`);
});

jobs.on("error", (err: Error) => {
  console.error("job failed", err);
});

export function startJob(id: string) {
  setTimeout(() => jobs.emit("error", new Error(`job ${id} failed`)), 10);
}
