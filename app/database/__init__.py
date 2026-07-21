
from collections.abc import AsyncGenerator, Generator
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import settings

# Fallback URLs
SYNC_URL = getattr(settings, "DATABASE_URL", "sqlite:///./fallback.db")
ASYNC_URL = getattr(settings, "ASYNC_DATABASE_URL", "sqlite+aiosqlite:///./fallback_async.db")

def get_engine_kwargs():
    # SQLite doesn't support pool_size, max_overflow, etc.
    if SYNC_URL.startswith("sqlite"):
        return {"echo": getattr(settings, "DB_ECHO", False)}
    return {
        "pool_size": getattr(settings, "DB_POOL_SIZE", 5),
        "max_overflow": getattr(settings, "DB_MAX_OVERFLOW", 10),
        "pool_timeout": getattr(settings, "DB_POOL_TIMEOUT", 30),
        "pool_recycle": getattr(settings, "DB_POOL_RECYCLE", 3600),
        "echo": getattr(settings, "DB_ECHO", False)
    }

engine = create_engine(SYNC_URL, **get_engine_kwargs())
async_engine = create_async_engine(ASYNC_URL, **get_engine_kwargs())

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
AsyncSessionLocal = async_sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase): pass

def get_db() -> Generator: 
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session: yield session
