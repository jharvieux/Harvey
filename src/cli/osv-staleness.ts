// Staleness check for the curated CVE corpus (issue #247). Re-queries api.osv.dev for every
// advisory this repo hardcodes (src/scan/dependencies.ts's CURATED_CLAIMS) and fails loudly when
// a claim no longer matches the upstream record:
//
//   - the advisory 404s or is withdrawn (rejected/retracted — CVE-2025-66478's fate), or
//   - OSV no longer lists our hardcoded fix boundary for our package.
//
//   pnpm osv-staleness
//
// NOT part of `pnpm verify`: it needs network, and verify must stay deterministic and offline.
// It runs on a schedule (.github/workflows/osv-staleness.yml), which is the point — drift arrives
// on the advisory's timeline, not on ours. #212 found a fabricated Critical (a CVSS-10 pre-auth
// RCE asserted against a next@14.2.x that was never affected) that had been shipping to real
// targets; every defect it found would have been caught mechanically by this check.

import "./sync-stdio.js";
import { CURATED_CLAIMS, type CuratedClaim } from "../scan/dependencies.js";

interface OsvEvent {
  introduced?: string;
  fixed?: string;
}
interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: { type?: string; events?: OsvEvent[] }[];
}
interface OsvVuln {
  id?: string;
  withdrawn?: string;
  affected?: OsvAffected[];
}

// OSV states a range as an event list; every `fixed` event names a first-patched version.
function fixedVersions(vuln: OsvVuln, pkg: string): string[] {
  const fixed: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== pkg) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed !== undefined) fixed.push(event.fixed);
      }
    }
  }
  return fixed;
}

async function checkClaim(claim: CuratedClaim): Promise<string | undefined> {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${claim.advisory}`);
  if (res.status === 404) return `${claim.advisory} 404s at OSV — withdrawn, rejected, or never existed`;
  if (!res.ok) return `${claim.advisory}: OSV returned HTTP ${res.status} — cannot verify`;

  const vuln = (await res.json()) as OsvVuln;
  if (vuln.withdrawn) return `${claim.advisory} was WITHDRAWN at OSV on ${vuln.withdrawn}`;

  const fixed = fixedVersions(vuln, claim.pkg);
  if (fixed.length === 0) return `${claim.advisory} lists no affected range for "${claim.pkg}" — we assert a fix at ${claim.fixed}`;
  if (!fixed.includes(claim.fixed)) {
    return `${claim.advisory} (${claim.pkg}): we assert a fix at ${claim.fixed}; OSV lists ${fixed.join(", ")}`;
  }
  return undefined;
}

async function main(): Promise<void> {
  console.log(`Verifying ${CURATED_CLAIMS.length} curated advisory claims against api.osv.dev\n`);

  const results = await Promise.all(
    CURATED_CLAIMS.map(async (claim) => ({ claim, drift: await checkClaim(claim) })),
  );
  const drifted = results.filter((r) => r.drift !== undefined);

  for (const { claim, drift } of results) {
    console.log(`  ${drift ? "DRIFT" : "ok   "}  ${claim.note}`);
    if (drift) console.log(`         ${drift}`);
  }

  if (drifted.length > 0) {
    console.error(`\n${drifted.length} of ${CURATED_CLAIMS.length} curated claims no longer match OSV.`);
    console.error("Each one is a fact this scanner asserts to clients. Re-verify against the advisory and correct src/scan/dependencies.ts (see #212).");
    process.exit(1);
  }
  console.log(`\nAll ${CURATED_CLAIMS.length} curated claims still match OSV.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
