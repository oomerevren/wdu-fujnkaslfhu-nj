"""
Start uvicorn, run API tests, then stop.
"""
import subprocess
import time
import urllib.request
import json
import sys
import os
import signal

VENV_PYTHON = 'python'
WORKDIR = os.getcwd()
BASE = 'http://127.0.0.1:8000'

# Kill any existing uvicorn
subprocess.run(['pkill', '-9', '-f', 'uvicorn'], capture_output=True, text=True, timeout=5)
time.sleep(1)

# Start uvicorn
proc = subprocess.Popen(
    [VENV_PYTHON, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    cwd=WORKDIR
)

# Wait for it to start
for i in range(20):
    time.sleep(1)
    try:
        req = urllib.request.Request(f'{BASE}/health')
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read())
            if data.get('status') == 'ok':
                print(f'Server started after {i+1}s')
                break
    except:
        pass
    if proc.poll() is not None:
        print('Server failed to start')
        out, err = proc.communicate()
        print(out.decode()[:1000])
        sys.exit(1)
else:
    print('Server did not start in time')
    proc.kill()
    sys.exit(1)

# Now run the tests
print('Running API tests...')
test_result = subprocess.run([VENV_PYTHON, 'test_api.py'], capture_output=True, text=True, timeout=90, cwd=WORKDIR)
print(test_result.stdout)
if test_result.stderr:
    print('STDERR:', test_result.stderr[-500:])

# Stop server
proc.terminate()
time.sleep(1)
if proc.poll() is None:
    proc.kill()

# Report
if test_result.returncode == 0:
    print('ALL TESTS PASSED!')
else:
    print('SOME TESTS FAILED')
    sys.exit(1)
