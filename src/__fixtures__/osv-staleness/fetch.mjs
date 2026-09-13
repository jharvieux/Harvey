// Offline OSV transport for the shipping CLI test. Every requested advisory gets an answer;
// an unexpected URL throws before any network request can escape this replacement fetch.
import { CURATED_CLAIMS } from "../../scan/dependencies.ts";

const scenario = process.env.HARVEY_OSV_STALENESS_SCENARIO ?? "valid";
const focus = CURATED_CLAIMS[0];
const claimsByAdvisory = new Map();
for (const claim of CURATED_CLAIMS) {
  const group = claimsByAdvisory.get(claim.advisory) ?? [];
  group.push(claim);
  claimsByAdvisory.set(claim.advisory, group);
}

function justBefore(fixed) {
  const prerelease = /^(.*-.*\.)(\d+)$/.exec(fixed);
  if (prerelease) return `${prerelease[1]}${Number(prerelease[2]) - 1}`;
  return `${fixed}-0`;
}

let requests = 0;
globalThis.fetch = async (url) => {
  requests++;
  const parsed = new URL(url);
  if (parsed.origin !== "https://api.osv.dev" || !parsed.pathname.startsWith("/v1/vulns/")) {
    throw new Error(`Unexpected OSV request ${url}`);
  }
  const id = parsed.pathname.slice("/v1/vulns/".length);
  const claims = claimsByAdvisory.get(id);
  if (!claims) throw new Error(`Unexpected advisory ${id}`);
  if (id === focus.advisory && scenario === "malformed_json") return new Response("{", { status: 200 });
  const affected = [...new Set(claims.map((claim) => claim.pkg))].map((name) => ({
    package: { name, ecosystem: "npm" },
    ranges: [...new Set(claims.filter((claim) => claim.pkg === name).map((claim) => claim.fixed))]
      .map((fixed) => ({ type: "SEMVER", events: [{ introduced: justBefore(fixed) }, { fixed }] })),
  }));
  if (id === focus.advisory) {
    const target = affected.find((entry) => entry.package.name === focus.pkg);
    if (!target) throw new Error("Focus claim missing from fixture");
    if (scenario === "overlap_open") target.ranges.push({ type: "SEMVER", events: [{ introduced: "0" }] });
    if (scenario === "explicit_version") target.versions = [focus.fixed];
    if (scenario === "wrong_ecosystem") target.package.ecosystem = "PyPI";
    if (scenario === "missing_ecosystem") delete target.package.ecosystem;
    if (scenario === "unsupported_range") target.ranges.push({ type: "ECOSYSTEM", events: [{ introduced: "0" }] });
    if (scenario === "malformed_event") target.ranges.push({ type: "SEMVER", events: [{ introduced: "0", fixed: focus.fixed }] });
    if (scenario === "malformed_versions") target.versions = "invalid";
    if (scenario === "limit_affects") target.ranges.push({ type: "SEMVER", events: [{ introduced: "0" }, { limit: "99.0.0" }] });
    if (scenario === "limit_excludes") target.ranges.push({ type: "SEMVER", events: [{ introduced: "0" }, { limit: "1.0.0" }] });
    if (scenario === "conflicting_events") target.ranges.push({ type: "SEMVER", events: [{ introduced: "0" }, { fixed: focus.fixed }, { introduced: focus.fixed }] });
  }
  return Response.json({ id, affected });
};

process.on("exit", () => console.error(`OFFLINE_FETCH_REQUESTS=${requests}`));
