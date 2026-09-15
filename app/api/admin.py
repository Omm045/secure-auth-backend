from fastapi import APIRouter,Depends,HTTPException
from app.services.session_service import current_user
from app.database.connection import transaction
from app.config import settings
router=APIRouter(prefix="/admin",tags=["admin"])
def admin(user=Depends(current_user)):
    if user["email"] not in settings.admin_emails: raise HTTPException(403,"Admin access required")
    return user
@router.get("/stats")
def stats(user=Depends(admin)):
    with transaction() as c:
        users=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]; logs=c.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]; breaches=c.execute("SELECT COUNT(*) FROM audit_logs WHERE event='password_breach'").fetchone()[0]
    return {"users":users,"audit_events":logs,"password_breaches":breaches}
