import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import { readEntriesLstatSafe } from '../src/fs-walk.js';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const runtime = process.argv[2];
if (!runtime)
    throw new Error('Usage: node --import tsx tools/stryker-ts7-acceptance.mjs <installed-runtime-directory>');
const modules = path.resolve(runtime, 'node_modules');
for (const [name, version] of Object.entries({ 'typescript': '7.0.2', '@stryker-mutator/core': '9.6.1', 'vitest': '3.2.6' }))
    assert.equal(JSON.parse(fs.readFileSync(path.join(modules, name, 'package.json'))).version, version);
const base = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'harvey-recovery-ts7-case-')));
const target = path.join(base, 'target');
fs.mkdirSync(target);
fs.cpSync(path.join(root, 'src/__fixtures__/mutation-runner-validity'), target, { recursive: true });
for (const f of ['vitest.config.ts', 'src/subject.ts', 'src/subject.test.ts'])
    fs.renameSync(path.join(target, f + '.txt'), path.join(target, f));
fs.symlinkSync(modules, path.join(target, 'node_modules'), 'dir');
fs.writeFileSync(path.join(base, 'base.json'), JSON.stringify({ compilerOptions: { target: 'ES2022', module: 'ESNext' } }));
fs.writeFileSync(path.join(target, 'tsconfig.json'), JSON.stringify({ extends: '../base.json', include: ['src/**/*.ts'] }));
const cfg = JSON.parse(fs.readFileSync(path.join(target, 'stryker.config.json')));
cfg.reporters = ['html'];
cfg.htmlReporter = { fileName: 'reports/mutation/index.html' };
fs.writeFileSync(path.join(target, 'stryker.config.json'), JSON.stringify(cfg, null, 2));
fs.mkdirSync(path.join(target, 'reports/mutation'), { recursive: true });
fs.writeFileSync(path.join(target, 'reports/mutation/index.html'), 'PREVIOUS REPORT');
const before = new Map();
const walk = d => { for (const e of readEntriesLstatSafe(d)) {
    if (e.name === 'node_modules')
        continue;
    if (e.isDirectory)
        walk(e.path);
    else
        before.set(e.path, fs.readFileSync(e.path));
} };
walk(target);
const out = path.join(base, 'engagement', 'm8.json');
fs.mkdirSync(path.dirname(out));
const run = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/mutation-scan.ts', target, '--out', out], { cwd: root, encoding: 'utf8', timeout: 55000, maxBuffer: 16 * 1024 * 1024 });
fs.writeFileSync(path.join(base, 'stderr.log'), run.stderr || '');
fs.writeFileSync(path.join(base, 'stdout.log'), run.stdout || '');
const changed = [...before].filter(([f, b]) => !fs.existsSync(f) || !fs.readFileSync(f).equals(b)).map(([f]) => f);
const artifact = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out)) : null;
const evidence = { base, target, out, status: run.status, error: run.error?.message, changed, raw: !!artifact?.rawReport, summary: artifact?.summary, receipt: artifact?.executionReceipt, ts7: JSON.parse(fs.readFileSync(path.join(modules, 'typescript/package.json'))).version };
fs.writeFileSync(path.join(base, 'acceptance.json'), JSON.stringify(evidence, null, 2));
console.log(JSON.stringify({ base, status: run.status, changed, raw: !!artifact?.rawReport, ts7: evidence.ts7, stderr: run.stderr?.slice(-1000) }, null, 2));
assert.equal(run.status, 0);
assert.deepEqual(changed, []);
assert.ok(artifact?.rawReport);
assert.match(run.stderr, /harvey-stryker-ts7-copy-target-/);
assert.equal(fs.readFileSync(path.join(target, 'reports/mutation/index.html'), 'utf8'), 'PREVIOUS REPORT');
assert.ok(artifact.executionReceipt.artifacts.every(a => fs.existsSync(a.path)));
const html = path.join(path.dirname(artifact.rawReport.config.jsonReporter.fileName), 'index.html');
assert.ok(fs.existsSync(html));
assert.ok(html.startsWith(path.dirname(out) + path.sep));
