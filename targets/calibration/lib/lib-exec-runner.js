import { exec } from "node:child_process";

// PLANTED BUG (P-LIB-CMD-INJECTION, #946): the exported function's parameter `target` is
// interpolated into a shell string run via child_process.exec — library-internal parameter-sourced
// OS command injection (the SecBench command-injection shape, request layer removed). Review tier.
export function ping(target, callback) {
  return exec(`ping -c 1 ${target}`, callback);
}

// PLANTED BUG (P-LIB-CODE-INJECTION, #946): the exported function's parameter `formula` is passed to
// eval — library-internal parameter-sourced code injection. Review tier.
export function compute(formula) {
  return eval(formula);
}
