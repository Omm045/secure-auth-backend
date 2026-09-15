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
    enforce_rate_limit(request,settings.rate_limit_per_minute,scope="forgot",identity=str(data.email))
    with transaction() as c: row=c.execute("SELECT id FROM users WHERE email=?",(data.email.lower(),)).fetchone()
    if row:
        issue_reset_token(row["id"], data.email.lower())
    return {"message":"If the account exists, reset instructions were sent"}
@router.post("/reset")
def reset(data:Reset,request:Request):
    verify_csrf(request); errors=validate_password(data.new_password)
    enforce_rate_limit(request,settings.rate_limit_per_minute,scope="reset",identity=token_hash(data.token))
    try:
        breached = breach_checker.is_breached(data.new_password)
    except Exception:
        # A password safety dependency outage must not silently allow risky passwords.
        raise HTTPException(503, "Password safety check unavailable")
    if errors or is_password_compromised(data.new_password) or breached:
        audit(None,"password_breach",request.client.host if request.client else None)
        raise HTTPException(422,detail=errors or ["Password has appeared in a breach"])
    race = False
    with transaction() as c:
        c.execute("DELETE FROM password_resets WHERE used=1 OR expires_at<=?", (datetime.now(timezone.utc).isoformat(),))
        row=c.execute("SELECT id,user_id FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?",(token_hash(data.token),datetime.now(timezone.utc).isoformat())).fetchone()
        if not row:
            audit(None,"reset_failure",request.client.host if request.client else None)
            raise HTTPException(400,"Invalid or expired reset token")
        # Conditional consumption prevents two concurrent requests from using one token.
        consumed = c.execute("UPDATE password_resets SET used=1 WHERE id=? AND used=0 AND expires_at>?",
                             (row["id"], datetime.now(timezone.utc).isoformat()))
        if consumed.rowcount != 1:
            race = True
        if race:
            pass
        else:
            c.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(data.new_password),row["user_id"]))
            c.execute("UPDATE password_resets SET used=1 WHERE user_id=?", (row["user_id"],))
            c.execute("UPDATE sessions SET revoked=1 WHERE user_id=?",(row["user_id"],))
    if race:
        audit(None,"reset_failure",request.client.host if request.client else None, {"reason": "token_race"})
        raise HTTPException(400, "Invalid or expired reset token")
    return {"message":"Password reset"}
