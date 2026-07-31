"use client";

// #1544 MEASURED GAP (P-CLIENT-HOOK-URL-PARAM) — the one row the destructuring requirement costs,
// planted so the cost is IN THE GATE rather than in a PR body. Modelled on the real instance that
// found it: carbon (crbnos/carbon@92e19c0)
// apps/erp/app/modules/production/ui/Jobs/JobBillOfProcess.tsx:444 → :655, where
// `const [params] = useUrlParams()` reaches a storage upload path. The pre-#1544 request-source
// block caught that flow BY NAME — for exactly the same reason it read a scheduler's DB rows as
// request input — so it was a true positive found by an unsound rule, and the binding requirement
// takes it with the false ones. MEASURED 2026-07-31 across all 17 pinned corpus repos: that single
// row is the entire recall cost (456 findings → 454, the other delta reproduced as semgrep
// nondeterminism under both rule sets).
//
// The shape is CLIENT-side, and the client source block (`x-dom-source`, xss.yml) already carries
// `useSearchParams()` and `$SP.get(...)` — but harvey-path-traversal is a server-side taint rule
// that takes `*request_source`, so no rule reaches this today. Which server-side sinks should also
// model client URL params is a per-rule judgment (shared-sources.test.ts's NARROW_BY_DESIGN /
// PENDING_JUDGMENT split), tracked on #1708. A rule firing here is a GATE FAIL that means the gap
// closed — re-rule this row when that happens.
declare function useUrlParams(): [URLSearchParams, (next: URLSearchParams) => void];
declare const supabase: {
  storage: { from(bucket: string): { upload(path: string, file: File, opts: { upsert: boolean }): Promise<void> } };
};

export function OperationAttachment({ companyId }: { companyId: string }) {
  const [params] = useUrlParams();
  const selectedOperation = params.get("selectedOperation");
  return async (file: File) => {
    const fileName = `${companyId}/parts/${selectedOperation}/${file.name}`;
    await supabase.storage.from("private").upload(fileName, file, { upsert: true });
  };
}
