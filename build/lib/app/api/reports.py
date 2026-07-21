from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from uuid import UUID
from app.database import get_db
from app.models.user import User
from app.services.auth_service import get_current_user
from app.services.report_service import generate_scan_report_pdf

router = APIRouter()

@router.get("/{scan_id}/pdf")
def get_scan_report_pdf(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        pdf_content = generate_scan_report_pdf(scan_id, current_user.id, db)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="pentestai-rapor-{scan_id}.pdf"'
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rapor oluşturulamadı: {str(e)}")
