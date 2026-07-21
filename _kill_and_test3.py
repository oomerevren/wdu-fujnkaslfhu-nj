import subprocess, time, urllib.request, json, os, sys

os.chdir(r'C:\Users\ömer\Documents\Default Project\faz1')
venv = r'C:\Users\ömer\.venv\Scripts\python.exe'

# Kill old
subprocess.run(['taskkill', '/F', '/IM', 'uvicorn.exe'], capture_output=True, text=True, timeout=5)
time.sleep(2)

# Start server - write ALL output to a file
with open('_server_all.log', 'wb') as log:
    proc = subprocess.Popen(
        [venv, '-u', '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    time.sleep(4)

    # Test register
    print('=== Testing Register ===')
    sys.stdout.flush()
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
    
    sys.stdout.flush()
    time.sleep(1)
    
    # Collect remaining output
    proc.kill()
    remaining, _ = proc.communicate(timeout=5)
    log.write(remaining)

# Read and display the log
with open('_server_all.log', 'rb') as f:
    content = f.read()

print('\n=== Server Output ===')
print(f'Total {len(content)} bytes')
print(content.decode('utf-8', errors='replace')[-2000:])
