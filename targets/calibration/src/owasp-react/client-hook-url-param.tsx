"use client";

// P-CLIENT-HOOK-URL-PARAM — planted by #1544 as the one row the RSC destructuring requirement
// cost, and CLOSED by #1708, which is why this row is now a normal review-tier positive rather than
// a recorded gap. Modelled on the real instance that found it: carbon (crbnos/carbon@92e19c0)
// apps/erp/app/modules/production/ui/Jobs/JobBillOfProcess.tsx:444 → :655, where
// `const [params] = useUrlParams()` reaches a storage upload path. The pre-#1544 request-source
// block caught that flow BY NAME — for exactly the same reason it read a scheduler's DB rows as
// request input — so it was a true positive found by an unsound rule, and the binding requirement
// took it with the false ones.
//
// #1708 reaches it properly: harvey-path-traversal's Supabase Storage sink is a supabase-js call a
// "use client" component can make with no server hop, so the rule now takes injection.yml's
// `x-client-url-source` alongside `*request_source`. MEASURED 2026-08-01, semgrep 1.164.0:
// `semgrep --config src/scan/rules/semgrep/injection.yml` on this file reports
// harvey-path-traversal on the `storage.from("private").upload(...)` call below, and nothing at
// all before the change. A row going DARK here is now the failure — it means the client-URL-param
// source stopped reaching this sink. (No line number: it moves whenever this header does.)
//
// What that source deliberately does NOT do is copy xss.yml's `x-dom-source` verbatim: its
// `$SP.get(...)` arm is receiver-agnostic, which a DOM-only sink can afford and a sink that runs on
// both sides may not. The receiver is bound to a URL-parameter-shaped name, and `params` below is
// why that vocabulary has to include the array-destructured spelling. The false-positive class the
// binding closes is scored in targets/calibration/src/client-url-source/.
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
