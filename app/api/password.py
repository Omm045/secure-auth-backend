from datetime import datetime, timezone
from fastapi import APIRouter,Request,Response,HTTPException
from pydantic import BaseModel,EmailStr
from app.database.connection import transaction
from app.security.tokens import token_hash
from app.security.hashing import hash_password
from app.services.password_policy import validate_password,is_password_compromised
from app.services.breach_checker import BreachChecker
from app.security.rate_limit import enforce_rate_limit
from app.security.csrf import verify_csrf
from app.services.audit_service import audit
from app.services.reset_service import issue_reset_token
from app.config import settings
router=APIRouter(prefix="/password",tags=["password"])
breach_checker=BreachChecker()
class Email(BaseModel): email:EmailStr
class Reset(BaseModel): token:str; new_password:str
@router.post("/forgot")
def forgot(data:Email,request:Request):
    enforce_rate_limit(request,settings.rate_limit_per_minute)
    with transaction() as c: row=c.execute("SELECT id FROM users WHERE email=?",(data.email.lower(),)).fetchone()
    if row:
        issue_reset_token(row["id"], data.email.lower())
    return {"message":"If the account exists, reset instructions were sent"}
@router.post("/reset")
def reset(data:Reset,request:Request):
    verify_csrf(request); errors=validate_password(data.new_password)
    if errors or is_password_compromised(data.new_password) or breach_checker.is_breached(data.new_password):
        audit(None,"password_breach",request.client.host if request.client else None)
        raise HTTPException(422,detail=errors or ["Password has appeared in a breach"])
    with transaction() as c:
        row=c.execute("SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?",(token_hash(data.token),datetime.now(timezone.utc).isoformat())).fetchone()
        if not row:
            audit(None,"reset_failure",request.client.host if request.client else None)
            raise HTTPException(400,"Invalid or expired reset token")
        c.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(data.new_password),row["user_id"])); c.execute("UPDATE password_resets SET used=1 WHERE id=?",(row["id"],)); c.execute("UPDATE sessions SET revoked=1 WHERE user_id=?",(row["user_id"],))
    return {"message":"Password reset"}
