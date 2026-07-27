import { pbkdf2Sync } from "node:crypto";
import { readFileSync } from "node:fs";

// OWASP Nodejs Security CS, Application Security: "Avoid blocking the event loop with CPU-intensive
// operations" and "Monitor event loop performance". Both calls in this request path are synchronous:
// the KDF is deliberately expensive and the file read blocks, so concurrent requests queue behind
// each one and the process stops serving anyone.
export function verifyPassword(password: string, salt: string): string {
  return pbkdf2Sync(password, salt, 600_000, 64, "sha512").toString("hex");
}

export function loadTemplate(name: string): string {
  return readFileSync(`./templates/${name}.html`, "utf8");
}
