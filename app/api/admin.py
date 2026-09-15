from fastapi import APIRouter,Depends,HTTPException
from app.services.session_service import current_user
from app.database.connection import transaction
router=APIRouter(prefix="/admin",tags=["admin"])
def require_admin(user=Depends(current_user)):
    if user["role"] != "admin": raise HTTPException(403,"Admin access required")
    return user
@router.get("/stats")
def stats(user=Depends(require_admin)):
    with transaction() as c:
        users=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]; logs=c.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]; breaches=c.execute("SELECT COUNT(*) FROM audit_logs WHERE event='password_breach'").fetchone()[0]
    return {"users":users,"audit_events":logs,"password_breaches":breaches}
