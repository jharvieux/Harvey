// Batch B10 — dependency-CVE & framework-version breadth (#71, spec
// docs/design/corpus-roadmap-to-100.md §3b). Extends the curated offline CVE ranges in
// src/scan/dependencies.ts (checkNextVersionCVEs's new null-origin row + CURATED_DEP_CVES) — no
// new scanner. Every positive is a crisp single-boundary version match, so all ten land `high`.
//
// Modelled with the B2 secondary-manifest mechanism: three STANDALONE fixture app-roots under
// targets/calibration/fixtures/, scanned offline by validate-calibration.ts's scanManifestFixtures
// (network/binary passes NOT re-run — these are all offline manifest facts). b10-vuln-deps pins the
// vulnerable versions, b10-patched-deps the patched counterparts (draws NOTHING), and
// b10-nextauth-csrf isolates the OAuth-CSRF next-auth version (which can't share the vuln manifest's
// email-misdelivery next-auth — one manifest, one next-auth). All versions are DATA ONLY, never
// installed. See GROUND-TRUTH.md §B10.
//
// DROPPED: P-MINIMIST-PROTO-CVE (roadmap §3b, review) — it is the SAME CVE-2021-44906 /
// minimist<1.2.6 range already landed at `high` by B2's P-DEP-CVE-CRITICAL. Re-landing it would
// duplicate that finding; re-tiering minimist to review would regress the shipped high positive; and
// the dev-only-transitive "clears" half is already modelled by the existing N-DEV-DEP negative. The
// curated check has no dev/prod distinction to make it a distinct class. See GROUND-TRUTH.md §B10.

import type { CorpusEntry } from "./types.js";

const VULN = "fixtures/b10-vuln-deps/package.json";
const PATCHED = "fixtures/b10-patched-deps/package.json";
const NEXT14 = "fixtures/b10-next14-rsc/package.json";

export const b10DepsEntries: CorpusEntry[] = [
  // --- POSITIVES (all high: crisp single-boundary curated ranges) ---
  { id: "P-NEXT-CVE-NULLORIGIN", kind: "positive", cls: "Framework CVE — Next Server Actions null-origin CSRF (CVE-2026-27978)", location: VULN, match: ["27978"], expectedTier: "high", expectedSeverity: "Medium", note: "next@16.0.5 falls in the CVE-2026-27978 range (>=16.0.1 <16.1.7, GHSA-mq59-m269-xvcx); checkNextVersionCVEs's 4th row emits DEP-CVE-2026-27978 at high. 16.0.5 also (correctly) trips the RSC-RCE and WS-SSRF ranges on the same manifest — those are distinct findings; match on the CVE number to isolate this class. Carried a descriptive id and a 'synthetic advisory' note until #212's OSV check found the real CVE." },
  { id: "P-JSONWEBTOKEN-CVE", kind: "positive", cls: "Dependency CVE — jsonwebtoken alg-confusion (CVE-2022-23540)", location: VULN, match: ["jsonwebtoken"], expectedTier: "high", expectedSeverity: "High", note: "jsonwebtoken@8.5.1 is below the 9.0.0 fix; checkKnownDependencyCVEs (curated, offline) emits DEP-CVE-2022-23540 at high (crisp <9.0.0 boundary; 9.0.0 makes `algorithms` mandatory). Patched negative jsonwebtoken@9.0.2 in b10-patched-deps." },
  { id: "P-NEXTAUTH-CSRF-CVE", kind: "positive", cls: "Dependency CVE — next-auth OAuth CSRF (CVE-2023-27490)", location: "fixtures/b10-nextauth-csrf/package.json", match: ["CVE-2023-27490"], expectedTier: "high", expectedSeverity: "High", note: "next-auth@4.19.0 is below the 4.20.1 fix; DEP-CVE-2023-27490 at high. Lives in its own fixture root because 4.19.0 also fires the email-misdelivery class (<4.24.12), and the email positive needs a DIFFERENT next-auth version (4.24.5, above this fix) — one manifest can declare next-auth once. Match on the CVE id to isolate from the co-firing email finding." },
  { id: "P-NEXTAUTH-EMAIL-CVE", kind: "positive", cls: "Dependency CVE — next-auth email-signin misdelivery (GHSA-5jpx-9hw9-2fx4)", location: VULN, match: ["5jpx"], expectedTier: "high", expectedSeverity: "Medium", note: "next-auth@4.24.5 is below the 4.24.12 fix but ABOVE the OAuth-CSRF fix (4.20.1), so it fires ONLY the email class (DEP-GHSA-5jpx-9hw9-2fx4) — proving the two next-auth checks have distinct boundaries. Match on '5jpx'. Patched negative next-auth@4.24.12 clears both classes." },
  { id: "P-FOLLOW-REDIRECTS-CVE", kind: "positive", cls: "Dependency CVE — follow-redirects proxy-auth leak (CVE-2024-28849)", location: VULN, match: ["follow-redirects"], expectedTier: "high", expectedSeverity: "Medium", note: "follow-redirects@1.15.4 is below the 1.15.6 fix; DEP-CVE-2024-28849 at high (crisp <1.15.6; Proxy-Authorization not cleared on cross-origin redirect). Patched negative follow-redirects@1.15.6." },
  { id: "P-AXIOS-SSRF-CVE", kind: "positive", cls: "Dependency CVE — axios baseURL SSRF (CVE-2025-27152)", location: VULN, match: ["axios"], expectedTier: "high", expectedSeverity: "High", note: "axios@1.7.2 is in the 1.x affected line (>=1.0.0 <1.8.2); DEP-CVE-2025-27152 at high (absolute URL overrides baseURL → SSRF + credential leak). Patched negative axios@1.8.2." },
  { id: "P-UNDICI-CVE-CLUSTER", kind: "positive", cls: "Dependency CVE — undici SSRF + cross-origin header leak (CVE-2022-35949 / CVE-2024-24758)", location: VULN, match: ["undici"], expectedTier: "high", note: "undici@5.7.0 is below BOTH curated undici fixes — the pathname SSRF (5.8.1, DEP-CVE-2022-35949) and the Proxy-Authorization cross-origin leak (5.28.3, DEP-CVE-2024-24758) — so one fixture yields two high findings (the merged cluster). Both cleared by the patched negative undici@5.28.3." },
  { id: "P-COOKIE-PKG-CVE", kind: "positive", cls: "Dependency CVE — cookie field injection (CVE-2024-47764)", location: VULN, match: ["cookie"], expectedTier: "high", expectedSeverity: "Low", note: "cookie@0.5.0 is below the 0.7.0 fix; DEP-CVE-2024-47764 at high (out-of-bounds chars in name/path/domain → field injection). Patched negative cookie@0.7.0." },
  { id: "P-WS-REDOS-CVE", kind: "positive", cls: "Dependency CVE — ws Sec-WebSocket-Protocol ReDoS (CVE-2021-32640)", location: VULN, match: ["CVE-2021-32640"], expectedTier: "high", expectedSeverity: "Medium", note: "ws@7.4.5 is in the 7.x affected line (>=7.0.0 <7.4.6); DEP-CVE-2021-32640 at high. Match on the CVE id (not 'ws', which is a substring of the co-firing next 'WebSocket-upgrade SSRF' finding). Patched negative ws@7.4.6." },
  { id: "P-SHARP-LIBWEBP-CVE", kind: "positive", cls: "Dependency CVE — sharp bundled-libwebp overflow (CVE-2023-4863)", location: VULN, match: ["sharp"], expectedTier: "high", expectedSeverity: "High", note: "sharp@0.31.3 is below the 0.32.6 fix (which bundles libwebp >= 1.3.2); DEP-CVE-2023-4863 at high (heap overflow decoding a crafted WebP → RCE/DoS). Patched negative sharp@0.32.6." },

  // --- NEGATIVES (patched versions — b10-patched-deps draws NOTHING) ---
  { id: "N-NEXT-NULLORIGIN-PATCHED", kind: "negative", cls: "Patched Next (null-origin fixed + WS-SSRF clear)", location: PATCHED, match: ["27978"], note: "next@16.2.5 is above the null-origin fix (16.1.7) AND the overlapping WS-SSRF range (<16.2.5), so checkNextVersionCVEs draws nothing at all — the truly-clean patched next-16. 16.1.7 would still carry a WS-SSRF high, so 16.2.5 is the correct clean negative for the whole next-16 CVE set." },
  { id: "N-NEXT-RSC-14X-UNAFFECTED", kind: "negative", cls: "Unaffected framework line inside a vulnerable major (Next 14.2 vs the RSC RCE)", location: NEXT14, match: ["55182"], note: "#212: next@14.2.35 must NOT draw CVE-2025-55182 — GHSA-9qr9-h5gf-34mp's ranges open at 14.3.0-canary.77, so no RELEASED 14.x is affected. This shipped as a `high` POSITIVE (base batch's P-NEXT-CVE-RSC) against a fabricated '14.2 fixed in 14.2.35' boundary until the OSV provenance check; every next@14.2.x target took a Critical FP. Re-registered as the negative pinning the range's lower edge. Its own fixture root: the root target's next@^14.2.5 shares the bare location 'next' with the b10 manifests' genuine RSC findings, which a substring match can't tell apart. 14.2.35 still (correctly) draws the WS-SSRF high — the '55182' keyword isolates this class. Genuine RSC positives live on the 15.x/16.0 lines." },
  { id: "N-JSONWEBTOKEN-PATCHED", kind: "negative", cls: "Patched jsonwebtoken", location: PATCHED, match: ["jsonwebtoken"], note: "jsonwebtoken@9.0.2 is at/above the 9.0.0 fix — outside the CVE-2022-23540 range, no finding." },
  { id: "N-NEXTAUTH-PATCHED", kind: "negative", cls: "Patched next-auth (both CSRF + email fixed)", location: PATCHED, match: ["next-auth"], note: "next-auth@4.24.12 is at/above both fixes (4.20.1 OAuth-CSRF, 4.24.12 email) — clears both curated classes with a single patched version." },
  { id: "N-FOLLOW-REDIRECTS-PATCHED", kind: "negative", cls: "Patched follow-redirects", location: PATCHED, match: ["follow-redirects"], note: "follow-redirects@1.15.6 is at the fix — outside the CVE-2024-28849 range, no finding." },
  { id: "N-AXIOS-PATCHED", kind: "negative", cls: "Patched axios", location: PATCHED, match: ["axios"], note: "axios@1.8.2 is at the fix — outside the CVE-2025-27152 range, no finding." },
  { id: "N-UNDICI-PATCHED", kind: "negative", cls: "Patched undici (both cluster CVEs fixed)", location: PATCHED, match: ["undici"], note: "undici@5.28.3 is at/above both fixes (5.8.1 SSRF, 5.28.3 header-leak) — clears the whole cluster." },
  { id: "N-COOKIE-PATCHED", kind: "negative", cls: "Patched cookie", location: PATCHED, match: ["cookie"], note: "cookie@0.7.0 is at the fix — outside the CVE-2024-47764 range, no finding." },
  { id: "N-WS-PATCHED", kind: "negative", cls: "Patched ws", location: PATCHED, match: ["CVE-2021-32640"], note: "ws@7.4.6 is at the fix — outside the CVE-2021-32640 range, no finding." },
  { id: "N-SHARP-PATCHED", kind: "negative", cls: "Patched sharp", location: PATCHED, match: ["sharp"], note: "sharp@0.32.6 is at the fix (bundles libwebp >= 1.3.2) — outside the CVE-2023-4863 range, no finding." },
];
