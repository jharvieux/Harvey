const cp = require("child_process");
export function run(command) { return cp.execSync(command); }
