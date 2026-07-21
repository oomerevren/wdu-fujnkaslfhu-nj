from collections.abc import AsyncGenerator, Generator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.exc import SQLAlchemyError, TimeoutError

from app.config import settings

# ── Sync engine (legacy) ─────────────────────────────────────────────────────
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_pre_ping=True,
    pool_recycle=settings.DB_POOL_RECYCLE,
    echo=settings.DB_ECHO,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Async engine ─────────────────────────────────────────────────────────────
async_engine = create_async_engine(
    settings.ASYNC_DATABASE_URL,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_pre_ping=True,
    pool_recycle=settings.DB_POOL_RECYCLE,
    echo=settings.DB_ECHO,
    pool_use_lifo=settings.DB_POOL_USE_LIFO,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


# ── Sync dependency ──────────────────────────────────────────────────────────
def get_db() -> Generator:
    """FastAPI dependency that provides a sync DB session."""
    db = SessionLocal()
    try:
        yield db
    except (TimeoutError, SQLAlchemyError) as exc:
        db.rollback()
        raise RuntimeError(f"Database operation failed: {exc}") from exc
    finally:
        db.close()


# ── Async dependency ─────────────────────────────────────────────────────────
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides an async DB session.

    Usage:
        @router.get("/")
        async def endpoint(db: AsyncSession = Depends(get_async_db)):
            ...
    """
    db = AsyncSessionLocal()
    try:
        yield db
        await db.commit()
    except (TimeoutError, SQLAlchemyError) as exc:
        await db.rollback()
        raise RuntimeError(f"Database operation failed: {exc}") from exc
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()
