import { spawnSync } from "node:child_process";
import { buildGitHistoryFixture } from "./src/scan/git-history-secret-gate.js";

const { dir, cleanup } = buildGitHistoryFixture();
const args = ["git", "--no-verification", "--results=unverified", "--json", `file://${dir}`];

const clean = spawnSync("trufflehog", args, { encoding: "utf8", maxBuffer: 1024 * 1024 * 16 });
const lines = clean.stdout.split("\n").filter((l) => l.trim().startsWith("{"));
console.log(`clean run: status=${clean.status} signal=${clean.signal} stdout=${clean.stdout.length}B jsonLines=${lines.length}`);

const missing = spawnSync("trufflehog", ["git", "--no-verification", "--results=unverified", "--json", "file:///nonexistent-harvey"], { encoding: "utf8" });
console.log(`missing repo: status=${missing.status} signal=${missing.signal} stdout=${missing.stdout.length}B`);

const truncated = spawnSync("trufflehog", args, { encoding: "utf8", maxBuffer: 64 });
console.log(`maxBuffer 64B: status=${truncated.status} signal=${truncated.signal} err=${truncated.error?.message ?? "none"} stdout=${truncated.stdout?.length ?? "null"}`);

const killed = spawnSync("sh", ["-c", `trufflehog ${args.map((a) => `'${a}'`).join(" ")} & p=$!; sleep 0.05; kill -9 $p; wait $p`], { encoding: "utf8" });
console.log(`SIGKILLed: status=${killed.status} signal=${killed.signal} stdout=${killed.stdout.length}B jsonLines=${killed.stdout.split("\n").filter((l) => l.trim().startsWith("{")).length}`);

cleanup();
