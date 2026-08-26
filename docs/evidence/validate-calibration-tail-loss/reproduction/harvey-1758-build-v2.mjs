import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { stripVTControlCharacters } from "node:util";

const historicalRoot = "/private/tmp/harvey-1758-r1-4acfe824";
const lateRoot = "/private/tmp/harvey-1758-late-27718611";
const outputRoot = "/private/tmp/harvey-1758-publication-v2";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const ansiNormalize = (text) => stripVTControlCharacters(text)
  .replace(/\r\n/g, "\n")
  .replace(/\r/g, "\n");

function firstImport(text) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const index = lines.findIndex((line) => /^import(?:\s|["'{*])/.test(line));
  return index === -1 ? null : { line: index + 1, text: lines[index] };
}

function verifyLines(row, logPath, errors) {
  if (!existsSync(logPath)) {
    errors.push({ kind: "missing-raw-log", jobId: row.jobId ?? row.job?.id, path: logPath });
    return null;
  }
  const raw = readFileSync(logPath);
  const rawSha256 = sha256(raw);
  const expectedSha = row.rawLogSha256 ?? row.logReceipt?.sha256;
  if (rawSha256 !== expectedSha) {
    errors.push({ kind: "raw-log-digest", jobId: row.jobId ?? row.job?.id, expectedSha, actualSha: rawSha256, path: logPath });
  }
  const normalized = ansiNormalize(raw.toString("utf8"));
  const lines = normalized.split("\n");
  const checked = [];
  for (const [group, entries] of Object.entries({
    filePassLines: row.filePassLines ?? [],
    seededPassLines: row.seededPassLines ?? [],
    unseededPassLines: row.unseededPassLines ?? [],
  })) {
    for (const entry of entries) {
      const actual = lines[entry.line - 1];
      if (actual !== entry.text) {
        errors.push({ kind: "raw-log-line", jobId: row.jobId ?? row.job?.id, group, line: entry.line, expected: entry.text, actual });
      }
      checked.push({ group, line: entry.line, text: entry.text });
    }
  }
  return {
    rawLogSha256: rawSha256,
    normalizedLogSha256: sha256(normalized),
    retainedLinesSha256: sha256(JSON.stringify(checked)),
    checkedLines: checked,
  };
}

function verifyGuards(guards, sourceRoot, errors, kind) {
  return guards.map((guard) => {
    const sourcePath = join(sourceRoot, guard.artifact);
    if (!existsSync(sourcePath)) {
      errors.push({ kind: "missing-source", sourceKind: kind, checkoutSha: guard.checkoutSha, path: sourcePath });
      return { ...guard, sourcePath, sourceVerification: null };
    }
    const source = readFileSync(sourcePath);
    const actualSha = sha256(source);
    if (actualSha !== guard.sha256) {
      errors.push({ kind: "source-digest", sourceKind: kind, checkoutSha: guard.checkoutSha, expectedSha: guard.sha256, actualSha, path: sourcePath });
    }
    const importLine = firstImport(source.toString("utf8"));
    if (!importLine || importLine.text !== 'import "./sync-stdio.js";' || importLine.line !== 19) {
      errors.push({ kind: "first-import", sourceKind: kind, checkoutSha: guard.checkoutSha, actual: importLine, path: sourcePath });
    }
    return {
      ...guard,
      sourceVerification: {
      sourceBytesSha256: actualSha,
      sourceBytesMatchReceipt: actualSha === guard.sha256,
      firstImport: importLine,
      retainedFirstImportSha256: sha256(JSON.stringify(importLine)),
      },
    };
  });
}

const errors = [];
const historicalRows = readJson(join(historicalRoot, "qualified-postfix-rows.json"));
const historicalGuards = readJson(join(historicalRoot, "checkout-source-qualification.json"));
const lateRows = readJson(join(lateRoot, "qualified-heavy-jobs-v2.json"))
  .filter((row) => row.disposition === "calibration-passed");
const lateGuards = readJson(join(lateRoot, "source-qualification-v2.json"));

if (historicalRows.length !== 154) errors.push({ kind: "historical-row-count", actual: historicalRows.length, expected: 154 });
if (historicalGuards.length !== 139) errors.push({ kind: "historical-guard-count", actual: historicalGuards.length, expected: 139 });
if (lateRows.length !== 109) errors.push({ kind: "late-calibration-row-count", actual: lateRows.length, expected: 109 });
if (lateGuards.length !== 98) errors.push({ kind: "late-guard-count", actual: lateGuards.length, expected: 98 });

const historicalLogVerifications = historicalRows.map((row) => ({
  jobId: row.jobId,
  verification: verifyLines(row, join(historicalRoot, row.rawLogArtifact), errors),
}));
const lateLogVerifications = lateRows.map((row) => ({
  jobId: row.job.id,
  verification: verifyLines(row, join(lateRoot, row.logReceipt.artifact), errors),
}));
const verifiedHistoricalGuards = verifyGuards(historicalGuards, historicalRoot, errors, "historical");
const verifiedLateGuards = verifyGuards(lateGuards, lateRoot, errors, "late");

const historicalCheckoutSet = new Set(historicalRows.map((row) => row.actualCheckoutSha));
const lateCheckoutSet = new Set(lateRows.map((row) => row.actualCheckoutSha));
for (const checkoutSha of historicalCheckoutSet) if (!historicalGuards.some((guard) => guard.checkoutSha === checkoutSha)) errors.push({ kind: "historical-missing-guard", checkoutSha });
for (const checkoutSha of lateCheckoutSet) if (!lateGuards.some((guard) => guard.checkoutSha === checkoutSha)) errors.push({ kind: "late-missing-guard", checkoutSha });

const supplemental = {
  schemaVersion: 1,
  purpose: "Lossless retained historical calibration-pass lines and checkout-source guard proof; includes a same-class late evidence projection audit.",
  inputReceipts: {
    historicalQualifiedRows: { path: `${historicalRoot}/qualified-postfix-rows.json`, sha256: sha256(readFileSync(join(historicalRoot, "qualified-postfix-rows.json"))) },
    historicalCheckoutGuards: { path: `${historicalRoot}/checkout-source-qualification.json`, sha256: sha256(readFileSync(join(historicalRoot, "checkout-source-qualification.json"))) },
    lateQualifiedHeavyJobs: { path: `${lateRoot}/qualified-heavy-jobs-v2.json`, sha256: sha256(readFileSync(join(lateRoot, "qualified-heavy-jobs-v2.json"))) },
    lateSourceGuards: { path: `${lateRoot}/source-qualification-v2.json`, sha256: sha256(readFileSync(join(lateRoot, "source-qualification-v2.json"))) },
  },
  historical: {
    qualifiedCalibrationPassRows: historicalRows,
    rawLogVerification: historicalLogVerifications,
    checkoutSourceGuards: verifiedHistoricalGuards,
    counts: { calibrationPassRows: historicalRows.length, uniqueCheckouts: historicalCheckoutSet.size, checkoutSourceGuards: historicalGuards.length },
  },
  lateProjectionAudit: {
    scope: "All late calibration-passed rows and all late checkout-source guards; non-calibration late job dispositions are already preserved as full outcomes in census-normalized.json and do not claim calibration-pass proof.",
    calibrationPassRows: lateRows.map((row) => ({
      runId: row.runId,
      attempt: row.attempt,
      event: row.event,
      headSha: row.headSha,
      runCreatedAt: row.runCreatedAt,
      disposition: row.disposition,
      actualCheckoutSha: row.actualCheckoutSha,
      job: row.job,
      logReceipt: row.logReceipt,
      filePassLines: row.filePassLines,
      seededPassLines: row.seededPassLines,
      unseededPassLines: row.unseededPassLines,
    })),
    rawLogVerification: lateLogVerifications,
    checkoutSourceGuards: verifiedLateGuards,
    counts: { calibrationPassRows: lateRows.length, uniqueCheckouts: lateCheckoutSet.size, checkoutSourceGuards: lateGuards.length },
  },
  integrity: { errors, verified: errors.length === 0 },
};

writeFileSync(join(outputRoot, "historical-qualified-supplemental.json"), `${JSON.stringify(supplemental, null, 2)}\n`);
console.log(JSON.stringify({
  output: join(outputRoot, "historical-qualified-supplemental.json"),
  historicalRows: historicalRows.length,
  historicalGuards: historicalGuards.length,
  lateCalibrationRows: lateRows.length,
  lateGuards: lateGuards.length,
  errors,
}, null, 2));
process.exitCode = errors.length === 0 ? 0 : 1;
