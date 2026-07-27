import vm from "node:vm";

// N-VM-LITERAL-SAFE (negative for P-OWASP-NODE-VM-SANDBOX): the script text is a fixed literal
// baked into the source, not a dynamic/attacker-influenced expression, and neither require nor
// process is handed into the context.
export function evaluateFixedRule(facts: Record<string, unknown>) {
  return vm.runInNewContext("facts.total > 100", facts);
}
