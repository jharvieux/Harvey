import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path('/private/tmp/harvey-sweep-1758')
stdio_only = '--stdio' in sys.argv
out = Path('/private/tmp/harvey-1758-current-19f8f57c' + ('-stdio' if stdio_only else ''))
out.mkdir(exist_ok=True, mode=0o700)
env = os.environ.copy()
env['PATH'] = '/Users/johnharvieux/.nvm/versions/node/v24.19.0/bin:/private/tmp/harvey-semgrep-1.173/bin:' + env['PATH']
env['pnpm_config_verify_deps_before_run'] = 'false'
env['HARVEY_HEAVY_CLI_TESTS'] = '1'
if stdio_only:
    env.pop('HARVEY_HEAVY_CLI_TESTS', None)
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
assert head == '19f8f57c3dd698438d0ee0212daed4b9e48decb3'
assert subprocess.check_output(['git', 'status', '--porcelain'], cwd=root) == b''
argv = ['pnpm', 'exec', 'vitest', 'run', 'src/cli/validate-calibration.test.ts', 'src/cli/sync-stdio.test.ts', '--reporter=default', '--reporter=json', '--outputFile.json=' + str(out / 'vitest.json')]
if stdio_only:
    argv.remove('src/cli/validate-calibration.test.ts')
receipt = {'head': head, 'argv': argv, 'cwd': str(root), 'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'environment': {'HARVEY_HEAVY_CLI_TESTS': '1', 'pnpm_config_verify_deps_before_run': 'false'}, 'versions': {}}
if stdio_only:
    receipt['environment']['HARVEY_HEAVY_CLI_TESTS'] = 'unset'
for tool in ('node', 'pnpm', 'semgrep', 'trufflehog', 'gitleaks', 'osv-scanner'):
    v = subprocess.run([tool, '--version'], cwd=root, env=env, capture_output=True, text=True, timeout=45)
    receipt['versions'][tool] = {'exitCode': v.returncode, 'stdout': v.stdout.strip(), 'stderr': v.stderr.strip()}
    assert v.returncode == 0, tool
receipt['sourceSha256'] = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in ('src/cli/validate-calibration.test.ts', 'src/cli/validate-calibration.ts', 'src/cli/sync-stdio.ts', 'src/cli/sync-stdio.test.ts')}
(out / 'started.json').write_text(json.dumps(receipt, indent=2) + '\n')
started = time.monotonic()
with (out / 'run.log').open('wb') as log:
    child = subprocess.Popen(argv, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    receipt['pid'] = child.pid
    try:
        receipt['exitCode'] = child.wait(timeout=600)
    except subprocess.TimeoutExpired:
        receipt['timedOut'] = True
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        receipt['exitCode'] = child.returncode
    finally:
        try:
            os.killpg(child.pid, signal.SIGTERM)
            receipt['remainingGroupTerminated'] = True
        except ProcessLookupError:
            receipt['remainingGroupTerminated'] = False
receipt['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
receipt['elapsedSeconds'] = time.monotonic() - started
receipt['logSha256'] = hashlib.sha256((out / 'run.log').read_bytes()).hexdigest()
if (out / 'vitest.json').exists():
    report = json.loads((out / 'vitest.json').read_text())
    receipt['vitest'] = {k: report[k] for k in ('success', 'numPassedTests', 'numFailedTests', 'numPendingTests', 'numTotalTests')}
    receipt['vitestSha256'] = hashlib.sha256((out / 'vitest.json').read_bytes()).hexdigest()
(out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ('head', 'exitCode', 'elapsedSeconds', 'logSha256')}, indent=2), flush=True)
raise SystemExit(receipt['exitCode'] if receipt['exitCode'] >= 0 else 1)
