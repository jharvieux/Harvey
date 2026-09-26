import "./sync-stdio.js";
import { resolve } from "node:path";
import { bundleAuditEvidenceRecipe, importLegacyAuditEvidence } from "../audit-evidence-import.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : undefined; };
const out = flag("--out");
try {
  if (!out) throw new Error("usage: pass-artifact-bundle --recipe <json> --out <new-bundle-dir> OR --legacy-document <json> --snapshot <json> --validation <json> --sbom <json> [--reconciliation <json>] [--mutation <json>] --out <new-bundle-dir>");
  if (flag("--recipe")) console.log(await bundleAuditEvidenceRecipe(resolve(flag("--recipe")!), resolve(out)));
  else {
    const document = flag("--legacy-document"), snapshot = flag("--snapshot"), validation = flag("--validation"), sbom = flag("--sbom");
    if (!document || !snapshot || !validation || !sbom) throw new Error("Legacy import requires document, snapshot, validation and SBOM; missing historical identity cannot be invented");
    const result = importLegacyAuditEvidence({ document: resolve(document), snapshot: resolve(snapshot), validation: resolve(validation), sbom: resolve(sbom), reconciliation: flag("--reconciliation"), mutation: flag("--mutation"), out: resolve(out) });
    console.log(JSON.stringify({ ...result, mode: "historical-evidence-only", currentExecution: false }));
  }
} catch (error) { console.error(`EVIDENCE BUNDLE FAIL — ${error instanceof Error ? error.message : String(error)}`); process.exit(1); }
