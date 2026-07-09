// dead/index.ts — PLANTED NEGATIVE (M5-N-PUBLIC-API): the package's declared
// public entry point (see package.json exports["."]). Nothing in this repo
// imports it — it exists for external consumers — so knip.json lists it
// under entry, keeping the file and its export silent instead of reporting
// a false "dead file"/"unused export".
export function publicApiHelper(value: string): string {
  return `public:${value}`;
}
