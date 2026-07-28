// M7 (code layer, #170) — oversized committed assets. A filesystem walk (not an AST pass):
// images/media checked into the repo above a size threshold are page-weight and repo-bloat
// candidates. Grouped like the advisor scan (one finding per asset class, worst-first
// instance list) so 40 fat images read as one report row, not forty.
//
// Findings are candidates, not verdicts (confidence: Review) — a 2 MB download brochure in
// public/ is fine; a 2 MB hero JPEG on the landing page is not. The instance list gives the
// auditor the worst offenders to check.

import { relative, sep } from "node:path";
import { readEntriesSafe, statSafe } from "../fs-walk.js";
import type { Finding } from "../findings.js";

const IMAGE_EXT = /\.(png|jpe?g|gif|webp|avif|bmp|tiff?|svg)$/i;
const MEDIA_EXT = /\.(mp4|webm|mov|avi|mp3|wav|flac|ogg)$/i;
const EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out)$/;

interface AssetWeightOptions {
  /** Flag images larger than this (bytes). Default 500 KB — well past "should be optimized/CDN'd". */
  imageThresholdBytes?: number;
  /** Flag audio/video larger than this (bytes). Default 5 MB. */
  mediaThresholdBytes?: number;
}

interface FatAsset {
  path: string;
  bytes: number;
}

function walk(root: string, dir: string, out: { images: FatAsset[]; media: FatAsset[] }, opts: Required<AssetWeightOptions>): void {
  for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
    if (isDirectory) {
      if (!EXCLUDED_DIR.test(entry)) walk(root, full, out, opts);
      continue;
    }
    const size = statSafe(full)?.size ?? 0;
    const path = relative(root, full).split(sep).join("/");
    if (IMAGE_EXT.test(entry) && size > opts.imageThresholdBytes) out.images.push({ path, bytes: size });
    else if (MEDIA_EXT.test(entry) && size > opts.mediaThresholdBytes) out.media.push({ path, bytes: size });
  }
}

function mb(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const INSTANCE_CAP = 10;

function groupFinding(id: string, kind: "image" | "media", assets: FatAsset[], threshold: number): Finding {
  const sorted = [...assets].sort((a, b) => b.bytes - a.bytes);
  const shown = sorted.slice(0, INSTANCE_CAP);
  const total = sorted.reduce((s, a) => s + a.bytes, 0);
  const worst = sorted[0];
  return {
    id,
    status: "Open",
    category: "Performance",
    title: `${sorted.length} committed ${kind}${sorted.length === 1 ? "" : kind === "media" ? " files" : "s"} over ${mb(threshold)} (${mb(total)} total)`,
    severity: "Perf",
    confidence: "Review",
    taxonomy: kind === "image" ? "M7 — Oversized committed images" : "M7 — Oversized committed media",
    location: worst ? worst.path : "",
    evidence:
      `Worst-first: ${shown.map((a) => `${a.path} (${mb(a.bytes)})`).join(", ")}` +
      (sorted.length > shown.length ? ` … and ${sorted.length - shown.length} more` : ""),
    impact:
      kind === "image"
        ? "Any of these served to a page ships megabytes before optimization; they also permanently bloat every clone of the repo. Confirm which are user-facing vs. downloadable-by-design."
        : "Large media in the repo bloats every clone and, if served directly, streams without range-request/CDN optimization.",
    fix:
      kind === "image"
        ? "Serve user-facing images through `next/image` (or a CDN with on-the-fly resizing), compress/convert to WebP/AVIF at source, and move originals out of the repo (object storage)."
        : "Host media in object storage/CDN (range requests, no repo bloat) and reference by URL.",
    value: 3,
    ease: 4,
    safety: 5,
  };
}

export function scanAssetWeight(dir: string, options?: AssetWeightOptions): Finding[] {
  const opts: Required<AssetWeightOptions> = {
    imageThresholdBytes: options?.imageThresholdBytes ?? 500 * 1024,
    mediaThresholdBytes: options?.mediaThresholdBytes ?? 5 * 1024 * 1024,
  };
  const out = { images: [] as FatAsset[], media: [] as FatAsset[] };
  walk(dir, dir, out, opts);

  const findings: Finding[] = [];
  if (out.images.length) findings.push(groupFinding("M7A-01", "image", out.images, opts.imageThresholdBytes));
  if (out.media.length) findings.push(groupFinding("M7A-02", "media", out.media, opts.mediaThresholdBytes));
  return findings;
}
