const { exec: execute } = require("node:child_process");
export function run(command) { return execute(command); }
