from fastapi import FastAPI
from app.core.logging import logger

app = FastAPI(title="PentestAI-Colab")

@app.on_event("startup")
async def startup_event():
    logger.info("Minimal server started successfully")

@app.get("/health")
async def health():
    return {"status": "healthy", "phase": 1}

# Gerekli route'ları manuel ekle veya mockla
@app.get("/api/v1/health")
async def api_health():
    return {"status": "healthy"}