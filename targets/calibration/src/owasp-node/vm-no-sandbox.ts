import vm from "node:vm";

// OWASP Nodejs Security CS, Platform Security: "Use vm module only within secure sandboxes."
// runInNewContext is not a security boundary — the guest reaches the host realm through the objects
// it is handed, and `require` is passed in outright here.
export function evaluateRule(expr: string, facts: Record<string, unknown>) {
  return vm.runInNewContext(expr, { ...facts, require, process });
}
