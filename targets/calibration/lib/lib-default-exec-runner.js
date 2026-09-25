import cp from "node:child_process";
export function run(command) { return cp.exec(command); }
