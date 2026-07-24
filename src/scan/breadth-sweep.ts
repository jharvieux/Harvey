// Ungraded breadth-sweep manifest (#899) — the DELIBERATELY UNGRADED counterpart to
// src/scan/external-corpus.ts.
//
// external-corpus.ts pins SIX repos and records a MEASURED baseline per module (counted/total),
// so a precision regression on real code fails `pnpm corpus-drift`. That is the graded tier.
//
// This file is the OPPOSITE by construction. It pins the ~16 Bucket A/B targets from #899 for a
// VOLUME sweep whose question is not "did precision drift?" but "what does real code in the wild
// look like, at scale, and where does the mechanical tier crash / stall / go silent / over-fire?"
// (#899's three products: mechanization candidates, an FP catalogue, and a population for #882).
//
// WHY A SEPARATE TYPE WITH NO BASELINE FIELD — this is the crux of #899/#900, not an accident:
//   An ungraded result must NEVER read as a scored one. CLAUDE.md's coverage doctrine is that an
//   ambiguous status is worse than a wrong one — a row saying "scanned, 14 findings" next to a
//   graded baseline gets read as coverage. So a BreadthTarget carries NO `modules`, NO `counted`,
//   NO `total`, NO MutationBaseline — there is nowhere here to write a number a scorer could grade
//   against. The runner (src/cli/breadth-sweep.ts) emits raw findings stamped `graded: false`; the
//   `breadth-sweep.test.ts` invariant asserts these two manifests share no slug and that a
//   BreadthTarget is not an ExternalTarget. Nothing in this file may ever gain a baseline field:
//   the moment it does, it belongs in external-corpus.ts and under corpus-drift, and this tier's
//   whole reason to exist (ungraded-by-construction) is gone.
//
// The commits below were resolved from each repo's default-branch HEAD on 2026-07-24 via
// `git ls-remote` (see scratch resolve-pins.sh) — a snapshot pin, not a curated one. Licences are
// from docs/test-targets.md's 2026-07-23 measurement (antoineross/Hikari, absent there, was read
// live from the GitHub API: MIT). Licence gates USE, not scanning: NONE/NOASSERTION means
// clone-and-scan locally is fine, vendoring/publishing per-repo source is not — #900's disclosure
// gate governs anything that leaves the repo, and aggregate statistics are the publishable unit.

type BreadthBucket = "supabase" | "prisma";

// Metadata only — pins + provenance for a reproducible clone-and-scan. There is deliberately no
// per-module field: see the header. If you find yourself wanting to add `counted` here, you want
// external-corpus.ts instead.
interface BreadthTarget {
  slug: string; // local clone dir name + artifact filename
  repo: string; // owner/name on GitHub
  commit: string; // resolved default-branch HEAD on 2026-07-24 — a snapshot pin
  defaultBranch: string;
  license: string;
  bucket: BreadthBucket;
  what: string; // one-line description (docs/test-targets.md)
}

export const BREADTH_SWEEP: BreadthTarget[] = [
  // Bucket A — Supabase
  { slug: "priceai", repo: "dimthink/PriceAI", commit: "7ba8b01b705ff09d4dcd081927efb91e5f7703f3", defaultBranch: "main", license: "NOASSERTION", bucket: "supabase", what: "AI-subscription price comparison" },
  { slug: "git-city", repo: "srizzon/git-city", commit: "bb4d9102af6126970bbce1fb3e20d818df4a535f", defaultBranch: "main", license: "AGPL-3.0", bucket: "supabase", what: "3D GitHub-profile visualiser" },
  { slug: "liam", repo: "liam-hq/liam", commit: "92156eac5ef497fffe5a64bad94d6856985273df", defaultBranch: "main", license: "Apache-2.0", bucket: "supabase", what: "ER-diagram generator" },
  { slug: "grida", repo: "gridaco/grida", commit: "643873382bb0855fa909494a2d887e03450de9d7", defaultBranch: "main", license: "Apache-2.0", bucket: "supabase", what: "Open canvas / form builder" },
  { slug: "wacrm", repo: "ArnasDon/wacrm", commit: "3180f06da6eaa73d84b09b99ea30b01e78db62f5", defaultBranch: "main", license: "MIT", bucket: "supabase", what: "Self-hostable WhatsApp CRM" },
  { slug: "atomic-crm", repo: "marmelab/atomic-crm", commit: "dce557e2741eab9e24453b9f59e64eb2ea92da6b", defaultBranch: "main", license: "MIT", bucket: "supabase", what: "CRM (React + shadcn + Supabase)" },
  { slug: "onlook", repo: "onlook-dev/onlook", commit: "423e2e924366419e418ee049093872d535eea41a", defaultBranch: "main", license: "Apache-2.0", bucket: "supabase", what: "AI-first design tool" },
  { slug: "supabase-cms-kit", repo: "paperclip-cms/supabase-cms-kit", commit: "469ca2a81c5f7afc4f54101676a815131611b617", defaultBranch: "main", license: "NONE", bucket: "supabase", what: "CMS API + UI layer" },
  { slug: "open-scouts", repo: "firecrawl/open-scouts", commit: "0d9b714c219aa1400c9d13c12af838a89da5d60f", defaultBranch: "main", license: "NONE", bucket: "supabase", what: "AI web-monitoring platform" },
  { slug: "elatoai", repo: "akdeb/ElatoAI", commit: "5a5e2166d97fb35edd8943a3f770893752c62115", defaultBranch: "main", license: "NOASSERTION", bucket: "supabase", what: "ESP32 realtime voice AI" },
  { slug: "hikari", repo: "antoineross/Hikari", commit: "c1f16f54ecc0b804567728f922999ad463af39e6", defaultBranch: "main", license: "MIT", bucket: "supabase", what: "Next.js 14 + Stripe + Supabase SaaS starter" },

  // Bucket B — Prisma / Postgres
  { slug: "documenso", repo: "documenso/documenso", commit: "c02dfaba1a89f346db785879d39d35a04ec3450b", defaultBranch: "main", license: "AGPL-3.0", bucket: "prisma", what: "DocuSign alternative" },
  { slug: "dub", repo: "dubinc/dub", commit: "f90e5041d2f95f470e5551c38e2a516bf94b7803", defaultBranch: "main", license: "NOASSERTION", bucket: "prisma", what: "Link-attribution platform" },
  { slug: "hexclave", repo: "hexclave/hexclave", commit: "eed88f5dd58aa95455c42509c7d79f3f5f7a0569", defaultBranch: "dev", license: "NOASSERTION", bucket: "prisma", what: "User-infrastructure platform" },
  { slug: "cal-diy", repo: "calcom/cal.diy", commit: "3894f37e14eae5082770f35ff1fde72110c0e6b6", defaultBranch: "main", license: "MIT", bucket: "prisma", what: "Scheduling infrastructure" },
  { slug: "amplication", repo: "amplication/amplication", commit: "7656495d27f0dceff89657590c3f14149e45c7a6", defaultBranch: "master", license: "NOASSERTION", bucket: "prisma", what: "Backend code generator" },
];
