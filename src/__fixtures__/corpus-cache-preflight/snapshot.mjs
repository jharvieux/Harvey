// The source is local, while the shipping loader still checks pins, bytes and OSV assessments.
import { loadCorpusAdvisorySnapshot as load } from "../../corpus-advisory-snapshot.ts";
export * from "../../corpus-advisory-snapshot.ts";
export function loadCorpusAdvisorySnapshot(slug, pin) {
  return load(slug, pin, { dir: process.env.HARVEY_PREFLIGHT_ADVISORIES });
}
