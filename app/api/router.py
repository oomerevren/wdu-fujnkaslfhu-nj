from fastapi import APIRouter
from app.api import auth, targets, scans, findings, reports, subscriptions, public

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(targets.router, prefix="/targets", tags=["Targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(findings.router, prefix="/findings", tags=["Findings"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(subscriptions.router, prefix="/subscriptions", tags=["Subscriptions"])
api_router.include_router(public.router, tags=["Public"])
