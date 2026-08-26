import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path
from collections import Counter

ROOT = Path('/private/tmp/harvey-1758-late-27718611')
ROWS = json.loads((ROOT / 'qualified-heavy-jobs.json').read_text())
RUN = 32935540351
JOBS = {98076012024, 98076012039, 98076012047}

def fetch(name, endpoint):
    argv = ['gh', 'api', endpoint]
    result = subprocess.run(argv, capture_output=True, timeout=60)
    (ROOT / name).write_bytes(result.stdout)
    receipt = dict(artifact=name, argv=argv, exitCode=result.returncode,
                   sha256=hashlib.sha256(result.stdout).hexdigest(), bytes=len(result.stdout),
                   capturedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    assert result.returncode == 0, result.stderr.decode()
    return receipt, result.stdout

meta_receipt, raw = fetch('completed-cutoff-jobs.json', f'repos/jharvieux/Harvey/actions/runs/{RUN}/attempts/1/jobs?per_page=100')
meta = json.loads(raw)
assert len(meta['jobs']) == meta['total_count']
jobs = {j['id']: j for j in meta['jobs']}
refresh = [meta_receipt]
for row in ROWS:
    job_id = row['job']['id']
    if job_id in JOBS:
        assert row['runId'] == RUN and row['attempt'] == 1
        assert jobs[job_id]['status'] == 'completed'
        row['job'] = jobs[job_id]
        receipt, raw = fetch(f'job-{job_id}-completed.log', f'repos/jharvieux/Harvey/actions/jobs/{job_id}/logs')
        row['initialUnavailableReceipt'] = row['logReceipt']
        row['logReceipt'] = receipt
        refresh.append(receipt)
    elif row['disposition'] == 'job-skipped':
        continue
    else:
        assert row['logReceipt']['exitCode'] == 0
        raw = (ROOT / row['logReceipt']['artifact']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == row['logReceipt']['sha256']
    text = re.sub(r'(?:\x1b|\^\[)\[[0-?]*[ -/]*[@-~]', '', raw.decode(errors='replace'))
    lines = text.splitlines()
    def hits(predicate):
        return [dict(line=i + 1, text=l) for i, l in enumerate(lines) if predicate(l)]
    row['filePassLines'] = hits(lambda l: bool(re.search(r'[✓✔]\s+src/cli/validate-calibration\.test\.ts\s+\(3 tests\)', l)))
    row['seededPassLines'] = hits(lambda l: '✓' in l and 'exits 1 when one caught review-tier positive is darkened' in l)
    row['unseededPassLines'] = hits(lambda l: '✓' in l and 'exits 0 on the committed corpus' in l)
    row['failureLines'] = hits(lambda l: ('FAIL' in l and 'src/cli/validate-calibration.test.ts' in l) or ('×' in l and 'validate-calibration' in l))
    row['fileMentions'] = hits(lambda l: 'src/cli/validate-calibration.test.ts' in l)
    row['executionMentions'] = [l for l in row['fileMentions'] if 'EXCLUDED from this run' not in l['text']]
    row['selectedFileLines'] = hits(lambda l: 'This shard runs:' in l or bool(re.search(r'Z\s+src/\S+\.test\.ts\s*$', l)))
    row['cancellationLines'] = hits(lambda l: 'The operation was canceled' in l or 'signal SIGTERM' in l)
    for i, line in enumerate(lines[:-1]):
        if 'git log -1 --format=%H' in line:
            match = re.search(r'\b([a-f0-9]{40})\b', lines[i + 1])
            row['actualCheckoutSha'] = match[1] if match else None
            row['checkoutLines'] = [dict(line=i + 1, text=line), dict(line=i + 2, text=lines[i + 1])]
            break
    if len(row['filePassLines']) == 1 and row['seededPassLines'] and row['unseededPassLines'] and not row['failureLines']:
        row['disposition'] = 'calibration-passed'
    elif row['failureLines']:
        row['disposition'] = 'calibration-failed'
    elif row['executionMentions'] and row['job']['conclusion'] == 'cancelled':
        row['disposition'] = 'calibration-selected-cancelled-without-result'
    elif row['executionMentions']:
        row['disposition'] = 'calibration-unqualified'
    else:
        row['disposition'] = 'no-calibration-execution-result'

sources = json.loads((ROOT / 'source-qualification.json').read_text())
known = {x['checkoutSha'] for x in sources}
for sha in sorted({r['actualCheckoutSha'] for r in ROWS if r['disposition'] == 'calibration-passed'} - known):
    assert sha and re.fullmatch('[0-9a-f]{40}', sha)
    argv = ['git', 'show', sha + ':src/cli/validate-calibration.ts']
    result = subprocess.run(argv, capture_output=True, timeout=30)
    assert result.returncode == 0
    name = f'sources/{sha}.ts'; (ROOT / name).write_bytes(result.stdout)
    first = re.findall(r'^import\s+[^\n]+', result.stdout.decode(), re.M)[0]
    sources.append(dict(checkoutSha=sha, receipt=dict(argv=argv, exitCode=0), artifact=name,
                        sha256=hashlib.sha256(result.stdout).hexdigest(), firstImport=first,
                        guardFirstImport=first == 'import "./sync-stdio.js";'))
assert all(s['guardFirstImport'] for s in sources)
summary = json.loads((ROOT / 'summary.json').read_text())
summary.update(schemaVersion=2, dispositions=dict(Counter(r['disposition'] for r in ROWS)),
               jobConclusions=dict(Counter(r['job']['conclusion'] for r in ROWS)),
               qualifiedSourceCount=len(sources), guardFirstImportCount=len(sources),
               ambiguous=[dict(runId=r['runId'], attempt=r['attempt'], jobId=r['job']['id']) for r in ROWS if r['disposition'] in ['calibration-unqualified', 'calibration-failed', 'unreadable']],
               parserCorrection='An EXCLUDED warning from the later shared-source test is not evidence that calibration was selected in this heavy job. Original parser-v1 receipts remain intact.',
               incompleteExecutions=[dict(runId=r['runId'], attempt=r['attempt'], jobId=r['job']['id'], conclusion=r['job']['conclusion']) for r in ROWS if r['disposition']=='calibration-selected-cancelled-without-result'])
for name, data in [('qualified-heavy-jobs-v2.json', ROWS), ('source-qualification-v2.json', sources), ('refresh-manifest.json', refresh), ('summary-v2.json', summary)]:
    (ROOT / name).write_text(json.dumps(data, indent=2) + '\n')
print(json.dumps(summary), flush=True)
