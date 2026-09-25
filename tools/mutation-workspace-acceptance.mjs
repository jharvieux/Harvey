import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readEntriesSafe } from '../src/fs-walk.ts';
import { validateFindings } from '../src/findings.ts';

const engine = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtime = resolve(process.argv[2] ?? '/private/tmp/harvey-stryker-ts7-runtime');
assert(existsSync(join(runtime, 'node_modules/@stryker-mutator/core/package.json')), 'Provide a provisioned local Stryker/Vitest runtime');
const root = realpathSync(mkdtempSync(join(tmpdir(), 'harvey-workspace-acceptance-')));
const put = (base, path, value) => { const full = join(base, path); mkdirSync(dirname(full), {recursive:true}); writeFileSync(full, typeof value === 'string' ? value : JSON.stringify(value)); };
const tree = (path, base = path) => readEntriesSafe(path).entries.filter(e=>e.name!=='node_modules').flatMap(e => e.isDirectory ? tree(join(path,e.name),base) : [[join(path,e.name).slice(base.length), createHash('sha256').update(readFileSync(join(path,e.name))).digest('hex')]]);

function fixture(name, members, mode = 'normal') {
  const dir = join(root, name);mkdirSync(dir);
  put(dir, 'package.json', { private:true, type:'module', workspaces:members, devDependencies:{vitest:'3.2.6'} });
  for (const member of members) {
    put(dir, `${member}/package.json`, {name:member.replaceAll('/','-'), type:'module',scripts:{test:'vitest run'},devDependencies:{vitest:'3.2.6'}});
    put(dir, `${member}/src/subject.ts`, 'export function subject(a:number,b:number) { return a + b; }\n');
    put(dir, `${member}/test/subject.test.ts`, `import {test,expect} from 'vitest';\n${mode==='zero-related'&&member.endsWith('rag') ? 'const subject=(a:number,b:number)=>a+b;' : "import {subject} from '../src/subject';"}\ntest('adds',()=>expect(subject(2,3)).toBe(5));\n`);
    put(dir, `${member}/test/unrelated.test.ts`, "import {test,expect} from 'vitest';test('unrelated must not execute',()=>expect(0).toBe(1));\n");
    const localConfig=name.startsWith('aop');
    // Repository-invoked fixtures explicitly choose their package root.
    put(dir, `${member}/vitest.config.ts`, `export default {${localConfig?"":`root:${JSON.stringify(member)},`}test:{include:['test/**/*.test.ts']}};\n`);
    put(dir, localConfig ? `${member}/stryker.config.json` : `stryker.${member.replaceAll('/','-')}.config.json`, {testRunner:'vitest',plugins:['@stryker-mutator/vitest-runner'],coverageAnalysis:'perTest',vitest:{configFile:localConfig?'vitest.config.ts':`${member}/vitest.config.ts`},mutate:[localConfig?'src/**/*.ts':`${member}/src/**/*.ts`],reporters:['html'],thresholds:{break:null}});
    put(dir, `${member}/reports/mutation/index.html`, 'PREVIOUS REPORT');
  }
  symlinkSync(join(runtime,'node_modules'),join(dir,'node_modules'),'dir');
  return dir;
}
function run(name, directory, flags = []) {
  const before=tree(directory);const out=join(root,`${name}.json`);
  const child=spawnSync(process.execPath,['--import','tsx','src/cli/mutation-scan.ts',directory,'--concurrency','1','--out',out,...flags],{cwd:engine,encoding:'utf8',maxBuffer:64*1024*1024});
  put(root,`${name}.stdout`,child.stdout??'');put(root,`${name}.stderr`,child.stderr??'');
  assert.equal(child.status,0,child.stderr);
  assert.deepEqual(tree(directory),before,'Target source/config/existing reports changed');
  const artifact=JSON.parse(readFileSync(out,'utf8'));
  const validation=validateFindings({meta:{client:'Local fixture',subtitle:'M8 proof',date:'2026-09-25',commit:'local',auditor:'Acceptance',confidential:true,overallHealth:0,tenantIsolation:'Not assessed',authModel:'Not assessed',headline:'Focused workspace proof',scope:'Fixture source',methodology:'Native local tests',outOfScope:'Other modules'},findings:artifact.findings});
  assert(validation.ok,JSON.stringify(validation));
  return {path:out,artifact};
}
const hotspots=join(root,'hotspots.txt'); writeFileSync(hotspots,'apps/main/src/subject.ts\n');
const atc=run('atc',fixture('atc-source',['apps/main','apps/rag']),['--hotspots',hotspots]);
assert.equal(atc.artifact.workspaceCoverage.complete,true,JSON.stringify(atc.artifact.moduleRecord));
for(const id of ['workspace:apps/main','workspace:apps/rag']) {
 const row=atc.artifact.workspaces.find(row=>row.id===id);assert(row,'Missing planned workspace');assert.equal(row.state,'complete');assert.equal(row.testCount,1);assert.equal(row.relatedTests.length,1);assert.equal(row.reportedSources.length,1);
 assert(row.receipts.at(-1).command.argv.includes(hotspots),'Protected hotspot input did not reach the workspace child');
 const report=row.artifact.rawReport;assert.equal(Object.keys(report.testFiles).length,1);assert(report.framework.version);assert(row.receipts.length>=3);
 assert(row.artifact.executionReceipt.artifacts.some(a=>a.role==='report'&&existsSync(a.path)));
}
const aopSource=fixture('aop-source',['apps/web','packages/content','packages/engine','packages/shared','packages/tools']);
put(aopSource,'apps/web/src/bridge.ts',"import {subject as engine} from '../../../packages/engine/src/subject'; import {subject} from './subject'; export const bridge=()=>subject(engine(1,2),4);\n");
put(aopSource,'apps/web/test/bridge.test.ts',"import {test,expect} from 'vitest'; import {bridge} from '../src/bridge'; test('uses sibling source',()=>expect(bridge()).toBe(7));\n");
const aop=run('aop',aopSource);
assert.equal(aop.artifact.workspaceCoverage.complete,true,JSON.stringify(aop.artifact.moduleRecord));
assert.equal(aop.artifact.workspaces.filter(row=>row.state==='complete').length,5);
const zero=run('zero-related',fixture('zero-source',['apps/main','apps/rag'],'zero-related'));
assert.equal(zero.artifact.workspaceCoverage.complete,false);
assert.equal(zero.artifact.workspaces.find(row=>row.id==='workspace:apps/main').state,'complete');
assert.equal(zero.artifact.workspaces.find(row=>row.id==='workspace:apps/rag').state,'discovery-failed');
assert(zero.artifact.findings.some(row=>row.location==='apps/rag/package.json'&&row.evidence.includes('zero related tests')));
const mixedSource=fixture('mixed-source',['apps/main','apps/none','apps/unsupported','apps/dry','apps/missing','apps/stryker-dry']);
rmSync(join(mixedSource,'apps/none/test'),{recursive:true});
const unsupported=join(mixedSource,'stryker.apps-unsupported.config.json');const unsupportedConfig=JSON.parse(readFileSync(unsupported,'utf8'));unsupportedConfig.testRunner='ava';writeFileSync(unsupported,JSON.stringify(unsupportedConfig));
const dry=join(mixedSource,'apps/dry/test/subject.test.ts');writeFileSync(dry,readFileSync(dry,'utf8').replace('toBe(5)','toBe(6)'));
const missingConfigPath=join(mixedSource,'stryker.apps-missing.config.json'); const missingConfig=JSON.parse(readFileSync(missingConfigPath,'utf8')); missingConfig.plugins=['@harvey-fixture/not-installed']; writeFileSync(missingConfigPath,JSON.stringify(missingConfig));
const strykerDry=join(mixedSource,'apps/stryker-dry/test/subject.test.ts'); writeFileSync(strykerDry,readFileSync(strykerDry,'utf8')+"test('instrumentation compatibility',()=>expect((globalThis).__stryker__).toBeUndefined());\n");
const mixed=run('mixed',mixedSource);
assert.equal(mixed.artifact.workspaces.find(row=>row.id==='workspace:apps/main').state,'complete');
assert.equal(mixed.artifact.workspaces.find(row=>row.id==='workspace:apps/none').state,'no-tests');
assert.equal(mixed.artifact.workspaces.find(row=>row.id==='workspace:apps/unsupported').state,'unsupported-runner');
assert.equal(mixed.artifact.workspaces.find(row=>row.id==='workspace:apps/dry').state,'dry-run-failed');
assert.equal(mixed.artifact.workspaces.find(row=>row.id==='workspace:apps/missing').state,'missing-report');
assert.equal(mixed.artifact.workspaces.find(row=>row.id==='workspace:apps/stryker-dry').state,'dry-run-failed');
assert(mixed.artifact.findings.some(row=>row.id.startsWith('M8-03-')&&row.severity==='Medium'),'Preserve the actual singular Stryker dry-run finding');
assert.equal(mixed.artifact.workspaceCoverage.complete,false);
assert(mixed.artifact.findings.some(row=>row.id.startsWith('M8-00-')&&row.location==='apps/none/package.json'&&row.severity==='High'));
const alternateSource=fixture('alternate-source',['apps/main','apps/rag']);
put(alternateSource,'stryker.rag-main-config.json',{testRunner:'vitest',plugins:['@stryker-mutator/vitest-runner'],vitest:{configFile:'apps/main/vitest.config.ts'},mutate:['apps/rag/src/**/*.ts'],reporters:['html']});
const alternate=run('alternate',alternateSource);
const alternateRag=alternate.artifact.workspaces.filter(row=>row.id.startsWith('workspace:apps/rag'));
assert.equal(alternateRag.length,2,'Distinct runner/configuration populations must execute separately');
assert.deepEqual(alternateRag.map(row=>row.state).sort(),['complete','discovery-failed']);
assert.equal(alternate.artifact.workspaces.find(row=>row.id==='workspace:apps/main').state,'complete');
assert.equal(alternate.artifact.workspaceCoverage.complete,false);
const overrideSource=fixture('override-source',['apps/main','apps/rag']);
const override=join(overrideSource,'stryker.apps-main.config.json');
const overrideOut=join(root,'override.json');
const prior=join(root,'prior.json'); writeFileSync(prior,'{}');
const overrideChild=spawnSync(process.execPath,['--import','tsx','src/cli/mutation-scan.ts',overrideSource,'--plan','--config',override,'--compare-run',prior,'--out',overrideOut],{cwd:engine,encoding:'utf8'});
assert.equal(overrideChild.status,0,overrideChild.stderr);
const overridePlan=JSON.parse(readFileSync(overrideOut,'utf8'));
assert(overridePlan.moduleRecord.note.includes('Requested --compare-run is not assessed'));
assert.equal(readFileSync(prior,'utf8'),'{}');
assert.deepEqual(overridePlan.mutationWorkspacePlan.workspaces.find(row=>row.id==='workspace:apps/main').selectedSources,['apps/main/src/subject.ts']);
assert.deepEqual(overridePlan.mutationWorkspacePlan.workspaces.find(row=>row.id==='workspace:apps/rag').unselectedSources,['apps/rag/src/subject.ts']);
const configurationControls=[];
for(const variant of ['relative-root','absolute-root','dir-local','dir-root','config-test-dir','dynamic-test-dir','explicit-package','alternate-build','repo-omitted-cross','portable-root-dir']) {
 const target=fixture(`aop-config-${variant}`,['apps/rag']);
 const local=join(target,'apps/rag'),configPath=join(local,'stryker.config.json');
 const config=JSON.parse(readFileSync(configPath,'utf8'));
 let vitest="export default {test:{include:['test/**/*.test.ts']}};\n";
 if(variant==='relative-root')vitest="export default {root:'.',test:{include:['test/**/*.test.ts']}};\n";
 if(variant==='absolute-root')vitest="import {fileURLToPath} from 'node:url'; export default {root:fileURLToPath(new URL('.',import.meta.url)),test:{include:['test/**/*.test.ts']}};\n";
 const directory=variant.startsWith('dir-')||variant.endsWith('test-dir');
 if(directory) {
  vitest=`export default {test:{include:['**/*.test.ts']${variant.endsWith('test-dir')?",dir:'test/unit'":''}}};\n`;
  if(variant==='dynamic-test-dir')vitest="export default ()=>({test:{include:['**/*.test.ts'],dir:'test/unit'}});\n";
  put(target,'apps/rag/test/unit/subject.test.ts',"import {test,expect} from 'vitest'; import {subject} from '../../src/subject'; test('unit',()=>expect(subject(2,3)).toBe(5));\n");
  put(target,'apps/rag/test/integration/subject.test.ts',"import {test,expect} from 'vitest'; import {subject} from '../../src/subject'; test('integration',()=>expect(subject(3,4)).toBe(7));\n");
  if(!variant.endsWith('test-dir'))config.vitest.dir=variant==='dir-root'?'apps/rag/test/unit':'test/unit';
 }
 put(target,'apps/rag/vitest.config.ts',vitest);
 if(variant==='portable-root-dir') {
  put(target,'apps/rag/vitest.config.ts',"import {fileURLToPath} from 'node:url'; export default {root:fileURLToPath(new URL('./nested/',import.meta.url)),test:{dir:fileURLToPath(new URL('./nested/test/',import.meta.url)),include:['**/*.test.ts']}};\n");
  put(target,'apps/rag/nested/test/subject.test.ts',"import {test,expect} from 'vitest'; import {subject} from '../../src/subject'; test('portable',()=>expect(subject(2,3)).toBe(5));\n");
 }
 if(variant==='repo-omitted-cross') {
  put(target,'apps/rag/vitest.config.ts',"export default {test:{include:['**/*.test.ts']}};\n");
  put(target,'test/cross.test.ts',"import {test,expect} from 'vitest'; import {subject} from '../apps/rag/src/subject'; test('cross-package',()=>expect(subject(4,5)).toBe(9));\n");
 }
 if(variant==='dir-root'||variant==='repo-omitted-cross') {
  rmSync(configPath);config.vitest.configFile='apps/rag/vitest.config.ts';config.mutate=['apps/rag/src/**/*.ts'];put(target,'stryker.config.json',config);
 } else put(target,'apps/rag/stryker.config.json',config);
 if(variant==='alternate-build')put(target,'apps/rag/stryker.blocked.config.json',{...config,buildCommand:'node -e "process.exit(23)"'});
 const nativePath=join(root,`${variant}.native.json`);
 const nativeArgv=[join(runtime,'node_modules/vitest/vitest.mjs'),'related','--run','--config',join(local,'vitest.config.ts'),'--reporter=json','--outputFile',nativePath,...(config.vitest.dir?['--dir',config.vitest.dir]:[]),join(local,'src/subject.ts')];
 const nativeCwd=variant==='dir-root'||variant==='repo-omitted-cross'?target:local;
 const native=spawnSync(process.execPath,nativeArgv,{cwd:nativeCwd,encoding:'utf8'});
 put(root,`${variant}.native.stdout`,native.stdout??'');put(root,`${variant}.native.stderr`,native.stderr??'');
 assert.equal(native.status,0,native.stderr);
 const nativeResult=JSON.parse(readFileSync(nativePath,'utf8'));assert.equal(nativeResult.numPassedTests,variant==='repo-omitted-cross'?2:1,'Original native configuration must select exactly the intended related test population');
 const execution=run(`configuration-${variant}`,target,variant==='explicit-package'?['--config',configPath]:[]);
 const rows=execution.artifact.workspaces.filter(row=>row.id.startsWith('workspace:apps/rag'));
 if(variant==='alternate-build') {
  assert.deepEqual(rows.map(row=>row.state).sort(),['complete','discovery-failed']);
  assert(rows.find(row=>row.state==='discovery-failed').reason.includes('buildCommand'));
  assert.equal(execution.artifact.workspaceCoverage.complete,false,'An unadapted build contract cannot borrow its sibling result');
 } else {assert.equal(rows.length,1);assert.equal(rows[0].state,'complete',rows[0].reason);assert.equal(execution.artifact.workspaceCoverage.complete,true);}
 const complete=rows.find(row=>row.state==='complete');
 if(complete) {
  const nativeFiles=nativeResult.testResults.map(test=>relative(target,test.name)).sort();
  assert.deepEqual([...complete.relatedTests].sort(),nativeFiles,'Discovery must retain the original native test files, including cross-package imports');
  assert.equal(complete.testCount,nativeResult.numPassedTests);
  assert.deepEqual(Object.keys(complete.artifact.rawReport.testFiles).sort(),nativeFiles,'Stryker must observe the same original native test population');
 }
 configurationControls.push({variant,artifact:execution.path,native:{argv:nativeArgv,cwd:nativeCwd,exitCode:native.status,path:nativePath,passed:nativeResult.numPassedTests},states:rows.map(row=>({id:row.id,state:row.state,testCount:row.testCount,relatedTests:row.relatedTests}))});
 rmSync(target,{recursive:true,force:true});
}
const emptySource=fixture('aop-explicit-empty',['apps/rag']);
const emptyConfig=join(emptySource,'apps/rag/stryker.empty.json');put(emptySource,'apps/rag/stryker.empty.json',{testRunner:'vitest',mutate:['missing/**/*.ts']});
const empty=run('explicit-zero-match',emptySource,['--config',emptyConfig]);
assert.equal(empty.artifact.workspaceCoverage.complete,false);assert.equal(empty.artifact.workspaceCoverage.reported,0);
assert(empty.artifact.mutationWorkspacePlan.gaps.some(reason=>reason.includes('Explicit mutation configuration')&&reason.includes('zero source files')));
assert(empty.artifact.findings.some(row=>row.evidence.includes('apps/rag/stryker.empty.json')&&row.evidence.includes('zero source files')),'The unresolved configuration origin must reach the finding population');
const evidence={root,engine,versions:Object.fromEntries(['vitest','@stryker-mutator/core','typescript'].map(name=>[name,JSON.parse(readFileSync(join(runtime,'node_modules',name,'package.json'),'utf8')).version])),atc:atc.path,aop:aop.path,zeroRelated:zero.path,mixed:mixed.path,alternate:alternate.path,configurationControls,explicitZeroMatch:empty.path};
put(root,'acceptance.json',evidence);console.log(JSON.stringify(evidence,null,2));
for(const name of ['atc-source','aop-source','zero-source','mixed-source','override-source','alternate-source'])rmSync(join(root,name),{recursive:true,force:true});
