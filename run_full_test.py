"""
Full test: start server, run tests, stop server
"""
import subprocess
import time
import urllib.request
import json
import sys
import os
import signal
import threading

VENV_PYTHON = r'C:\Users\ömer\.venv\Scripts\python.exe'
WORKDIR = r'C:\Users\ömer\Documents\Default Project\faz1'
BASE = 'http://127.0.0.1:8000'
API = f'{BASE}/api/v1'

PASS = 0
FAIL = 0
server_proc = None

def log(msg):
    print(f'[TEST] {msg}')
    sys.stdout.flush()

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        log(f'  PASS: {name}')
        PASS += 1
    except AssertionError as e:
        log(f'  FAIL: {name} - {e}')
        FAIL += 1
    except Exception as e:
        log(f'  FAIL: {name} - {type(e).__name__}: {e}')
        FAIL += 1

def req(method, path, data=None, token=None):
    url = f'{BASE}{path}' if path == '/health' else f'{API}{path}'
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    body = json.dumps(data).encode() if data else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
        except:
            err_body = {'detail': str(e)}
        return e.code, err_body
    except urllib.error.URLError as e:
        raise Exception(f'Connection failed: {e.reason}')

# Start server
log('Starting server...')
subprocess.run(['taskkill', '/F', '/IM', 'uvicorn.exe'], capture_output=True, text=True, timeout=5)
time.sleep(1)

server_proc = subprocess.Popen(
    [VENV_PYTHON, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    cwd=WORKDIR
)

# Wait for server
for i in range(15):
    time.sleep(1)
    try:
        status, data = req('GET', '/health')
        if status == 200 and data.get('status') == 'ok':
            log(f'Server started after {i+1}s')
            break
    except:
        pass
    if server_proc.poll() is not None:
        log(f'Server died! Exit code: {server_proc.returncode}')
        out, err = server_proc.communicate()
        log(f'STDOUT: {out.decode()[:500]}')
        log(f'STDERR: {err.decode()[:500]}')
        sys.exit(1)
else:
    log('Server did not start')
    server_proc.kill()
    sys.exit(1)

# ===== TESTS =====
log('\\n=== HEALTH ===')
def health():
    status, data = req('GET', '/health')
    assert status == 200, f'Expected 200, got {status}'
    assert data['status'] == 'ok'
test('/health returns ok', health)

log('\\n=== AUTH ===')
token = None
def register():
    global token
    status, data = req('POST', '/auth/register', {'email': 'test@pentestai.com', 'password': 'Test123!', 'full_name': 'Test User'})
    assert status == 200, f'Expected 200, got {status}: {data}'
    assert data['access_token'] is not None
    token = data['access_token']
test('register creates user', register)

def register_dup():
    status, data = req('POST', '/auth/register', {'email': 'test@pentestai.com', 'password': 'Test123!'})
    assert status == 400, f'Expected 400, got {status}'
test('register duplicate returns 400', register_dup)

def login():
    global token
    status, data = req('POST', '/auth/login', {'email': 'test@pentestai.com', 'password': 'Test123!'})
    assert status == 200, f'Expected 200, got {status}: {data}'
    token = data['access_token']
test('login works', login)

def login_wrong():
    status, data = req('POST', '/auth/login', {'email': 'test@pentestai.com', 'password': 'wrong'})
    assert status == 401, f'Expected 401, got {status}'
test('login wrong password returns 401', login_wrong)

def get_me():
    status, data = req('GET', '/auth/me', token=token)
    assert status == 200
    assert data['email'] == 'test@pentestai.com'
test('get me returns user', get_me)

log('\\n=== TARGETS ===')
target_id = None
def create_target():
    global target_id
    status, data = req('POST', '/targets/', {'name': 'Test', 'url': 'https://example.com', 'target_type': 'web'}, token=token)
    assert status == 201, f'Expected 201, got {status}: {data}'
    target_id = data['id']
test('create target', create_target)

def list_targets():
    status, data = req('GET', '/targets/', token=token)
    assert status == 200
    assert len(data) > 0
test('list targets', list_targets)

log('\\n=== SCANS ===')
scan_id = None
def create_scan():
    global scan_id
    status, data = req('POST', '/scans/', {'target_id': target_id, 'scan_type': 'nuclei'}, token=token)
    assert status == 201, f'Expected 201, got {status}: {data}'
    scan_id = data['id']
test('create scan', create_scan)

def list_scans():
    status, data = req('GET', '/scans/', token=token)
    assert status == 200
test('list scans', list_scans)

log('\\n=== FINDINGS ===')
def list_findings():
    status, data = req('GET', '/findings/', token=token)
    assert status == 200
test('list findings', list_findings)

def stats_findings():
    status, data = req('GET', '/findings/stats', token=token)
    assert status == 200
    assert 'severity_distribution' in data
test('findings stats', stats_findings)

log('\\n=== SUBSCRIPTION ===')
def my_plan():
    status, data = req('GET', '/subscriptions/my-plan', token=token)
    assert status == 200
    assert data['plan'] == 'free'
test('my-plan returns free', my_plan)

# ===== SUMMARY =====
log('\\n' + '='*40)
log(f'RESULTS: {PASS} passed, {FAIL} failed out of {PASS+FAIL} tests')
log('='*40)

# Stop server
server_proc.terminate()
time.sleep(1)
if server_proc.poll() is None:
    server_proc.kill()

if FAIL > 0:
    sys.exit(1)
else:
    log('ALL TESTS PASSED!')
