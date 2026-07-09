import fs from "node:fs";
import path from "node:path";
import AdmZip from "adm-zip";

// PLANTED BUG (P-ZIP-SLIP): each archive entry name is joined into a write path with no
// containment check — a `../` entry name writes outside outDir (zip-slip). Review tier.
export function extractAll(zipPath, outDir) {
  const zip = new AdmZip(zipPath);
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory) continue;
    fs.writeFileSync(path.join(outDir, entry.entryName), entry.getData());
  }
}
