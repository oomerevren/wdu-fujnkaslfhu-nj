import subprocess, time, urllib.request, json, os, sys

os.chdir(r'C:\Users\ömer\Documents\Default Project\faz1')
venv = r'C:\Users\ömer\.venv\Scripts\python.exe'

# Kill old
subprocess.run(['taskkill', '/F', '/IM', 'uvicorn.exe'], capture_output=True, text=True, timeout=5)
time.sleep(2)

# Start server with stderr redirected to a file
err_file = open('_server_err.log', 'wb')
proc = subprocess.Popen(
    [venv, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'],
    stdout=subprocess.PIPE, stderr=err_file
)
time.sleep(4)

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
    print('Body:', body[:200])
except Exception as e:
    print('ERROR:', e)

# Stop server
time.sleep(2)
proc.kill()
proc.wait(timeout=5)
err_file.close()

# Read the error log (as raw bytes and try to decode)
with open('_server_err.log', 'rb') as f:
    raw = f.read()

print('\n=== Server STDERR (raw hex) ===')
# Print as hex to avoid encoding issues
print(f'Total {len(raw)} bytes')
# Find the traceback - look for "Traceback" in bytes
idx = raw.find(b'Traceback')
if idx >= 0:
    print(f'Found Traceback at byte {idx}')
    print(raw[idx:idx+2000].decode('utf-8', errors='replace'))
else:
    print('No Traceback found in stderr')
    print('First 500 bytes:', raw[:500])
    print('Last 500 bytes:', raw[-500:])
