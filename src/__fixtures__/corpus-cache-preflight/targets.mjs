import { readFileSync } from "node:fs";
export * from "../../scan/external-corpus.ts";
export const EXTERNAL_CORPUS = JSON.parse(readFileSync(process.env.HARVEY_PREFLIGHT_TARGETS, "utf8"));
export const FREE_TIER_EXPECTATIONS = [];
