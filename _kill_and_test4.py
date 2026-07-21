import subprocess, time, urllib.request, json, os, sys

os.chdir(r'C:\Users\ömer\Documents\Default Project\faz1')
venv = r'C:\Users\ömer\.venv\Scripts\python.exe'

# Kill old
subprocess.run(['taskkill', '/F', '/IM', 'uvicorn.exe'], capture_output=True, text=True, timeout=5)
time.sleep(2)

# Start server, redirect ALL output to a file
with open('_server_out.txt', 'w', encoding='utf-8') as out:
    out.write('=== Starting server ===\n')
    out.flush()

proc = subprocess.Popen(
    [venv, '-u', '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'],
    stdout=open('_server_out.txt', 'a', encoding='utf-8'),
    stderr=subprocess.STDOUT
)
time.sleep(5)

# Check if still alive
if proc.poll() is not None:
    with open('_server_out.txt', 'a', encoding='utf-8') as f:
        f.write(f'\n=== Process exited with code {proc.returncode} ===\n')

# Test register
with open('_server_out.txt', 'a', encoding='utf-8') as f:
    f.write('=== Testing Register ===\n')

data = json.dumps({'email': 'test@pentestai.com', 'password': 'Test123!', 'full_name': 'Test User'}).encode()
req = urllib.request.Request('http://127.0.0.1:8000/api/v1/auth/register', data=data,
                            headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        with open('_server_out.txt', 'a', encoding='utf-8') as f:
            f.write(f'SUCCESS: {resp.status} {resp.read().decode()[:300]}\n')
except urllib.error.HTTPError as e:
    with open('_server_out.txt', 'a', encoding='utf-8') as f:
        f.write(f'HTTP ERROR: {e.code}\n')
        body = e.read()
        f.write(f'Body: {body[:500]}\n')
except Exception as e:
    with open('_server_out.txt', 'a', encoding='utf-8') as f:
        f.write(f'ERROR: {e}\n')

time.sleep(2)

# Kill and collect remaining output
try:
    proc.kill()
    proc.wait(timeout=5)
except:
    pass

with open('_server_out.txt', 'a', encoding='utf-8') as f:
    f.write('\n=== END ===\n')

print('Done. Check _server_out.txt')
