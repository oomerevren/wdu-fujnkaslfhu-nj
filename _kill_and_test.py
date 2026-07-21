"""
Kill old servers, start fresh, test register, report.
"""
import subprocess, time, urllib.request, json, os, sys

os.chdir(r'C:\Users\ömer\Documents\Default Project\faz1')
venv = r'C:\Users\ömer\.venv\Scripts\python.exe'

# Kill old
subprocess.run(['taskkill', '/F', '/IM', 'uvicorn.exe'], capture_output=True, text=True, timeout=5)
time.sleep(2)

# Start server
proc = subprocess.Popen(
    [venv, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
time.sleep(3)

# Test register
print('=== Testing Register ===')
data = json.dumps({'email': 'test@pentestai.com', 'password': 'Test123!', 'full_name': 'Test User'}).encode()
req = urllib.request.Request('http://127.0.0.1:8000/api/v1/auth/register', data=data,
                            headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        print('SUCCESS:', resp.status)
        print('Body:', resp.read().decode()[:300])
except urllib.error.HTTPError as e:
    print('HTTP ERROR:', e.code)
    body = e.read()
    print('Body:', body[:500])
except Exception as e:
    print('ERROR:', e)

# Get server logs
time.sleep(1)
proc.kill()
out, err = proc.communicate(timeout=5)

# The stderr might have non-utf8 chars, use replace
print('\n=== Server STDOUT (last 500) ===')
print(out.decode('utf-8', errors='replace')[-500:])
print('\n=== Server STDERR (last 1000) ===')
print(err.decode('utf-8', errors='replace')[-1000:])
