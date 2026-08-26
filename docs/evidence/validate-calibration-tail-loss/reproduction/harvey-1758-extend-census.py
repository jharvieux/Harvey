import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

OUT = Path('/private/tmp/harvey-1758-late-27718611')
FROM = '2026-08-14T07:26:58Z'
TO = '2026-08-26T05:49:10Z'
REPO = 'repos/jharvieux/Harvey'
os.umask(0o077)
OUT.mkdir(exist_ok=True, mode=0o700)

def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + '\n')

def get(name, endpoint, raw=False):
    assert endpoint.startswith(REPO + '/')
    argv = ['gh', 'api', endpoint]
    result = subprocess.run(argv, capture_output=True, timeout=120)
    (OUT / name).write_bytes(result.stdout)
    receipt = dict(artifact=name, argv=argv, exitCode=result.returncode,
                   sha256=hashlib.sha256(result.stdout).hexdigest(),
                   bytes=len(result.stdout), capturedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    if result.returncode:
        receipt['error'] = result.stderr.decode(errors='replace')[:500]
        return receipt, None
    return receipt, result.stdout if raw else json.loads(result.stdout)

manifest = []
runs = []
total = None
for page in range(1, 11):
    receipt, data = get(f'runs-page-{page}.json', f'{REPO}/actions/workflows/ci.yml/runs?created={FROM}..{TO}&per_page=100&page={page}')
    manifest.append(receipt)
    assert data is not None, receipt
    assert data['total_count'] <= 1000, 'Split the time window; API result cap exceeded'
    total = data['total_count'] if total is None else total
    assert data['total_count'] == total, 'Population changed during pagination'
    runs.extend(data['workflow_runs'])
    if len(runs) >= total:
        break
assert len(runs) == total == len({r['id'] for r in runs})
save('window-runs.json', runs)
attempts = [(r, a) for r in runs for a in range(1, r['run_attempt'] + 1)]
print(json.dumps(dict(runs=len(runs), attempts=len(attempts))), flush=True)

def attempt(item):
    run, number = item
    jobs = []
    receipts = []
    for page in range(1, 11):
        receipt, data = get(f'jobs-{run["id"]}-a{number}-p{page}.json', f'{REPO}/actions/runs/{run["id"]}/attempts/{number}/jobs?per_page=100&page={page}')
        receipts.append(receipt)
        assert data is not None, receipt
        jobs.extend(data['jobs'])
        if len(jobs) >= data['total_count']:
            assert len(jobs) == data['total_count'] == len({j['id'] for j in jobs})
            break
    else:
        raise RuntimeError('Jobs pagination overflow')
    return dict(runId=run['id'], attempt=number, event=run['event'], headSha=run['head_sha'],
                runCreatedAt=run['created_at'], jobs=jobs, receipts=receipts)

with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    records = []
    for i, record in enumerate(pool.map(attempt, attempts), 1):
        records.append(record)
        if i % 25 == 0:
            print(json.dumps(dict(attemptsCollected=i, total=len(attempts))), flush=True)
save('all-attempts.json', records)
manifest.extend(receipt for r in records for receipt in r['receipts'])
heavy = []
for record in records:
    for job in record['jobs']:
        if 'heavy cli tests' in job['name'].lower():
            heavy.append({k: record[k] for k in ['runId', 'attempt', 'event', 'headSha', 'runCreatedAt']} | dict(job=job))
assert len(heavy) == len({(r['runId'], r['attempt'], r['job']['id']) for r in heavy})
print(json.dumps(dict(allHeavyJobAttempts=len(heavy))), flush=True)

def qualify(row):
    job = row['job']
    if job['conclusion'] == 'skipped':
        return row | dict(disposition='job-skipped', logReceipt=None)
    receipt, raw = get(f'job-{job["id"]}.log', f'{REPO}/actions/jobs/{job["id"]}/logs', raw=True)
    if raw is None:
        return row | dict(disposition='unreadable', logReceipt=receipt)
    clean = re.sub(r'(?:\x1b|\^\[)\[[0-?]*[ -/]*[@-~]', '', raw.decode(errors='replace'))
    lines = clean.splitlines()
    checkout = None
    checkout_lines = []
    for i, line in enumerate(lines[:-1]):
        if 'git log -1 --format=%H' in line:
            match = re.search(r'\b([a-f0-9]{40})\b', lines[i + 1])
            checkout = match[1] if match else None
            checkout_lines = [dict(line=i + 1, text=line), dict(line=i + 2, text=lines[i + 1])]
            break
    file_pass = [dict(line=i + 1, text=l) for i, l in enumerate(lines) if re.search(r'[✓✔]\s+src/cli/validate-calibration\.test\.ts\s+\(3 tests\)', l)]
    seeded = [dict(line=i + 1, text=l) for i, l in enumerate(lines) if '✓' in l and 'exits 1 when one caught review-tier positive is darkened' in l]
    unseeded = [dict(line=i + 1, text=l) for i, l in enumerate(lines) if '✓' in l and 'exits 0 on the committed corpus' in l]
    failures = [dict(line=i + 1, text=l) for i, l in enumerate(lines) if ('FAIL' in l and 'src/cli/validate-calibration.test.ts' in l) or ('×' in l and 'validate-calibration' in l)]
    mentions = [dict(line=i + 1, text=l) for i, l in enumerate(lines) if 'src/cli/validate-calibration.test.ts' in l]
    disposition = 'calibration-passed' if len(file_pass) == 1 and seeded and unseeded and not failures else 'calibration-failed' if failures else 'calibration-unqualified' if mentions else 'no-calibration-result'
    return row | dict(disposition=disposition, logReceipt=receipt, actualCheckoutSha=checkout,
                      checkoutLines=checkout_lines, filePassLines=file_pass, seededPassLines=seeded,
                      unseededPassLines=unseeded, failureLines=failures, fileMentions=mentions)

qualified = []
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    for i, row in enumerate(pool.map(qualify, heavy), 1):
        qualified.append(row)
        if i % 25 == 0:
            print(json.dumps(dict(logsQualified=i, total=len(heavy))), flush=True)
save('qualified-heavy-jobs.json', qualified)
manifest.extend(r['logReceipt'] for r in qualified if r['logReceipt'])

shas = sorted({r['actualCheckoutSha'] for r in qualified if r['disposition'] == 'calibration-passed' and r['actualCheckoutSha']})
(OUT / 'sources').mkdir(exist_ok=True)
def source(sha):
    assert re.fullmatch('[0-9a-f]{40}', sha)
    argv = ['git', 'show', sha + ':src/cli/validate-calibration.ts']
    result = subprocess.run(argv, capture_output=True, timeout=30)
    receipt = dict(argv=argv, exitCode=result.returncode)
    if result.returncode:
        receipt, data = get(f'sources/{sha}.api.json', f'{REPO}/contents/src/cli/validate-calibration.ts?ref={sha}')
        if data is None:
            return dict(checkoutSha=sha, receipt=receipt, guardFirstImport=False)
        raw = base64.b64decode(data['content'])
    else:
        raw = result.stdout
    name = f'sources/{sha}.ts'
    (OUT / name).write_bytes(raw)
    imports = re.findall(r'^import\s+[^\n]+', raw.decode(), re.M)
    return dict(checkoutSha=sha, receipt=receipt, artifact=name, sha256=hashlib.sha256(raw).hexdigest(),
                firstImport=imports[0] if imports else None, guardFirstImport=bool(imports and imports[0] == 'import "./sync-stdio.js";'))
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    sources = list(pool.map(source, shas))
save('source-qualification.json', sources)
from collections import Counter
summary = dict(schemaVersion=1, window=dict(runCreatedFromInclusive=FROM, runCreatedToInclusive=TO),
               reboundHead='277186113abba0b5de71ac8cdeaa2632ddd747cd', queriedRuns=len(runs),
               runAttempts=len(attempts), allHeavyJobAttempts=len(heavy),
               dispositions=dict(Counter(r['disposition'] for r in qualified)),
               jobConclusions=dict(Counter(r['job']['conclusion'] for r in qualified)),
               qualifiedSourceCount=len(sources), guardFirstImportCount=sum(r['guardFirstImport'] for r in sources),
               ambiguous=[dict(runId=r['runId'], attempt=r['attempt'], jobId=r['job']['id'], disposition=r['disposition']) for r in qualified if r['disposition'] in ['unreadable','calibration-failed','calibration-unqualified']],
               note='Every heavy shard is inspected because selective routing can move calibration away from shard 2. No-result or skipped jobs are not calibration passes.')
save('download-manifest.json', manifest)
save('summary.json', summary)
print(json.dumps(summary), flush=True)
