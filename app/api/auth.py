from datetime import datetime,timedelta,timezone
import sqlite3
from fastapi import APIRouter,Request,Response,HTTPException,Depends,BackgroundTasks
from pydantic import BaseModel,EmailStr,Field
from app.database.connection import transaction
from app.security.hashing import hash_password,verify_password
from app.services.password_policy import validate_password,is_password_compromised
from app.services.breach_checker import BreachChecker
from app.services.session_service import create_session,current_user,revoke
from app.services.audit_service import audit
from app.security.rate_limit import (
    enforce_rate_limit, enforce_account_failure_limit, record_account_failure,
    clear_account_failures,
)
from app.security.csrf import verify_csrf
from app.config import settings
from app.security.cookies import set_session_cookie, clear_session_cookie
from app.services.reset_service import issue_verification_token
from app.security.tokens import token_hash
from psycopg.errors import UniqueViolation
router=APIRouter(prefix="/auth",tags=["auth"])
breach_checker = BreachChecker()
DUMMY_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$u7Pu1zpy3Um6fOGyEpJIfA$HYGl3GFHFglhpCKLF2UHfunnxAzAzyCa8tBXLHS49sA"
def reject_password(password, user_id=None):
    errors=validate_password(password)
    if errors: raise HTTPException(422,detail=errors)
    try:
        breached = breach_checker.is_breached(password)
    except Exception:
        raise HTTPException(503, "Password safety check unavailable")
    if is_password_compromised(password) or breached:
        if user_id: audit(user_id,"password_breach")
        raise HTTPException(422,"Password has appeared in a breach")
class Credentials(BaseModel):
    email: EmailStr = Field(max_length=320)
    password: str = Field(max_length=128)

class PasswordChange(BaseModel):
    current_password: str = Field(max_length=128)
    new_password: str = Field(max_length=128)

def set_session(response,raw,exp): set_session_cookie(response, raw, exp)
@router.post("/register",status_code=201)
def register(data:Credentials,request:Request,response:Response,background_tasks: BackgroundTasks):
    enforce_rate_limit(request,settings.rate_limit_per_minute,scope="register",identity=str(data.email)); reject_password(data.password)
    try:
        with transaction() as c:
            email = data.email.lower()
            if c.execute("SELECT 1 FROM users WHERE lower(email)=lower(?)", (email,)).fetchone():
                return {"message": "If registration is available, verification instructions will be sent"}
            role = "user"
            c.execute("INSERT INTO users(email,password_hash,created_at,role,email_verified) VALUES(?,?,?,?,FALSE)",
                      (email,hash_password(data.password),datetime.now(timezone.utc).isoformat(),role))
            uid=c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()[0 if hasattr(c, "cursor") else "id"]
    except (sqlite3.IntegrityError, UniqueViolation):
        return {"message": "If registration is available, verification instructions will be sent"}
    background_tasks.add_task(issue_verification_token, uid, email)
    audit(uid,"register",request.client.host if request.client else None)
    return {"message": "If registration is available, verification instructions will be sent"}
@router.post("/login")
def login(data:Credentials,request:Request,response:Response):
    enforce_rate_limit(request,settings.rate_limit_per_minute,scope="login",identity=str(data.email))
    enforce_account_failure_limit(str(data.email), settings.rate_limit_per_minute)
    with transaction() as c: row=c.execute("SELECT * FROM users WHERE email=?",(data.email.lower(),)).fetchone()
    password_hash = row["password_hash"] if row else DUMMY_PASSWORD_HASH
    password_valid = verify_password(data.password, password_hash)
    if not row or row["disabled"] or not password_valid:
        record_account_failure(str(data.email))
        if row: audit(row["id"],"login_failure",request.client.host if request.client else None)
        raise HTTPException(401,"Invalid credentials")
    clear_account_failures(str(data.email))
    with transaction() as c: c.execute("UPDATE users SET last_login=? WHERE id=?",(datetime.now(timezone.utc).isoformat(),row["id"]))
    raw,exp=create_session(row["id"]); set_session(response,raw,exp); audit(row["id"],"login",request.client.host if request.client else None); return {"message":"Logged in"}
@router.post("/logout")
def logout(request:Request,response:Response):
    verify_csrf(request); revoke(request); clear_session_cookie(response); return {"message":"Logged out"}
@router.get("/me")
def me(user=Depends(current_user)): return {"id":user["id"],"email":user["email"],"email_verified":bool(user["email_verified"])}

class VerificationRequest(BaseModel):
    token_value: str = Field(min_length=20, max_length=256)

@router.post("/verify-email")
def verify_email(data: VerificationRequest, request: Request):
    token_value = data.token_value
    enforce_rate_limit(
        request, settings.rate_limit_per_minute, scope="verify",
        identity=token_hash(token_value),
    )
    now = datetime.now(timezone.utc).isoformat()
    with transaction() as c:
        row = c.execute("SELECT id,user_id FROM email_verification_tokens WHERE token_hash=? AND used=FALSE AND expires_at>?",
                        (token_hash(token_value), now)).fetchone()
        if not row:
            raise HTTPException(400, "Invalid or expired verification token")
        c.execute("UPDATE email_verification_tokens SET used=TRUE WHERE id=? AND used=FALSE", (row["id"],))
        c.execute("UPDATE users SET email_verified=TRUE WHERE id=?", (row["user_id"],))
    return {"message": "Email verified"}
@router.post("/change-password")
def change(data:PasswordChange,request:Request,response:Response,user=Depends(current_user)):
    verify_csrf(request); reject_password(data.new_password,user["id"])
    if not verify_password(data.current_password,user["password_hash"]): raise HTTPException(401,"Invalid current password")
    with transaction() as c:c.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(data.new_password),user["id"])); c.execute("UPDATE sessions SET revoked=TRUE WHERE user_id=?",(user["id"],))
    clear_session_cookie(response); audit(user["id"],"change_password"); return {"message":"Password changed"}
