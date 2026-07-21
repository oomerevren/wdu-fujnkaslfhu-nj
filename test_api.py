"""
PentestAI API Test Script
Tests health, auth, targets, scans, and findings endpoints.
"""
import urllib.request
import json
import sys

BASE = 'http://127.0.0.1:8000'
API_PREFIX = '/api/v1'
PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        print(f'  [PASS] {name}')
        PASS += 1
    except Exception as e:
        print(f'  [FAIL] {name}: {e}')
        FAIL += 1

def request(method, path, data=None, token=None):
    if path == '/health':
        url = f'{BASE}{path}'
    else:
        url = f'{BASE}{API_PREFIX}{path}'
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except urllib.error.URLError as e:
        raise Exception(f'Connection failed: {e.reason}')

# ===== Health =====
print('\\n=== HEALTH CHECK ===')
def health():
    status, data = request('GET', '/health')
    assert status == 200, f'Expected 200, got {status}'
    assert data['status'] == 'ok', f'Expected ok, got {data}'
test('GET /health returns ok', health)

# ===== Auth =====
print('\\n=== AUTH ===')
token = None

def register():
    global token
    status, data = request('POST', '/auth/register', {
        'email': 'test@pentestai.com',
        'password': 'Test123!',
        'full_name': 'Test User'
    })
    assert status == 200, f'Expected 200, got {status}: {data}'
    assert data['access_token'] is not None
    assert data['user']['email'] == 'test@pentestai.com'
    token = data['access_token']
test('POST /auth/register creates user', register)

def register_duplicate():
    status, data = request('POST', '/auth/register', {
        'email': 'test@pentestai.com',
        'password': 'Test123!'
    })
    assert status == 400, f'Expected 400 for duplicate, got {status}'
test('POST /auth/register duplicate returns 400', register_duplicate)

def login():
    global token
    status, data = request('POST', '/auth/login', {
        'email': 'test@pentestai.com',
        'password': 'Test123!'
    })
    assert status == 200, f'Expected 200, got {status}'
    assert data['access_token'] is not None
    token = data['access_token']
test('POST /auth/login works', login)

def login_wrong():
    status, data = request('POST', '/auth/login', {
        'email': 'test@pentestai.com',
        'password': 'WrongPassword!'
    })
    assert status == 401, f'Expected 401, got {status}'
test('POST /auth/login wrong password returns 401', login_wrong)

def get_me():
    status, data = request('GET', '/auth/me', token=token)
    assert status == 200
    assert data['email'] == 'test@pentestai.com'
test('GET /auth/me returns user', get_me)

# ===== Onboarding =====
print('\\n=== ONBOARDING ===')

def onboarding_company():
    status, data = request('POST', '/auth/onboarding/company', 
                          {'company_name': 'PentestAI Test'}, token=token)
    assert status == 200
    assert data['onboarding_step'] == 'target'
test('POST /auth/onboarding/company works', onboarding_company)

def onboarding_status():
    status, data = request('GET', '/auth/onboarding/status', token=token)
    assert status == 200
    assert data['onboarding_step'] == 'target'
test('GET /auth/onboarding/status returns step', onboarding_status)

# ===== Targets =====
print('\\n=== TARGETS ===')

def create_target():
    status, data = request('POST', '/targets/', {
        'name': 'Test Target',
        'url': 'https://example.com',
        'target_type': 'web'
    }, token=token)
    assert status == 201, f'Expected 201, got {status}: {data}'
    assert data['url'] == 'https://example.com'
    global target_id
    target_id = data['id']
test('POST /targets/ creates target', create_target)

def list_targets():
    status, data = request('GET', '/targets/', token=token)
    assert status == 200
    assert len(data) > 0
test('GET /targets/ lists targets', list_targets)

def get_target():
    status, data = request('GET', f'/targets/{target_id}', token=token)
    assert status == 200
    assert data['id'] == target_id
test('GET /targets/{id} returns target', get_target)

# ===== Scans =====
print('\\n=== SCANS ===')

scan_id = None
def create_scan():
    global scan_id
    status, data = request('POST', '/scans/', {
        'target_id': target_id,
        'scan_type': 'nuclei'
    }, token=token)
    assert status == 201, f'Expected 201, got {status}: {data}'
    assert data['status'] == 'queued' or data['status'] == 'running'
    scan_id = data['id']
test('POST /scans/ creates scan', create_scan)

def list_scans():
    status, data = request('GET', '/scans/', token=token)
    assert status == 200
    assert len(data) > 0
test('GET /scans/ lists scans', list_scans)

# ===== Findings =====
print('\\n=== FINDINGS ===')

def list_findings():
    status, data = request('GET', '/findings/', token=token)
    assert status == 200
test('GET /findings/ works', list_findings)

def stats_findings():
    status, data = request('GET', '/findings/stats', token=token)
    assert status == 200
    assert 'severity_distribution' in data
test('GET /findings/stats works', stats_findings)

# ===== Subscription =====
print('\\n=== SUBSCRIPTION ===')

def my_plan():
    status, data = request('GET', '/subscriptions/my-plan', token=token)
    assert status == 200
    assert data['plan'] == 'free'
test('GET /subscriptions/my-plan returns free', my_plan)

# ===== Summary =====
print(f'\\n{"="*40}')
print(f'RESULTS: {PASS} passed, {FAIL} failed out of {PASS+FAIL} tests')
print(f'{"="*40}')
if FAIL > 0:
    sys.exit(1)
else:
    print('ALL TESTS PASSED!')
