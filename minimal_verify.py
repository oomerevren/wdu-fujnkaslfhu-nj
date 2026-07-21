from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get('/')
async def root():
    return {'status': 'healthy', 'phase': 'Phase 1 Verified'}

@app.get('/health')
async def health():
    return {'status': 'healthy', 'phase': 'Phase 1 Verified'}

if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8080)