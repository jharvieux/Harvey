import { EventEmitter } from "node:events";

// OWASP Nodejs Security CS, Error & Exception Handling: "Always listen to error events when using
// EventEmitter objects" and "Bind to uncaughtException event and clean up resources before exit."
// An EventEmitter that emits 'error' with no listener terminates the process, and nothing here
// installs a handler or cleans up.
export const jobs = new EventEmitter();

jobs.on("done", (id: string) => {
  console.log(`job ${id} finished`);
});

export function startJob(id: string) {
  setTimeout(() => jobs.emit("error", new Error(`job ${id} failed`)), 10);
}
