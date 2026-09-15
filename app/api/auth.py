from datetime import datetime,timedelta,timezone
from fastapi import APIRouter,Request,Response,HTTPException,Depends
from pydantic import BaseModel,EmailStr
from app.database.connection import transaction
from app.security.hashing import hash_password,verify_password
from app.services.password_policy import validate_password,is_password_compromised
from app.services.breach_checker import BreachChecker
from sqlite3 import IntegrityError
from app.services.session_service import create_session,current_user,revoke
from app.services.audit_service import audit
from app.security.rate_limit import enforce_rate_limit
from app.security.csrf import verify_csrf
from app.config import settings
from app.security.cookies import set_session_cookie, clear_session_cookie
router=APIRouter(prefix="/auth",tags=["auth"])
breach_checker = BreachChecker()
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
class Credentials(BaseModel): email:EmailStr; password:str
class PasswordChange(BaseModel): current_password:str; new_password:str

def set_session(response,raw,exp): set_session_cookie(response, raw, exp)
@router.post("/register",status_code=201)
def register(data:Credentials,request:Request,response:Response):
    enforce_rate_limit(request,settings.rate_limit_per_minute,scope="register",identity=str(data.email)); reject_password(data.password)
    with transaction() as c:
        try:
            email = data.email.lower()
            role = "admin" if email in {item.lower() for item in settings.admin_emails} else "user"
            c.execute("INSERT INTO users(email,password_hash,created_at,role) VALUES(?,?,?,?)",
                      (email,hash_password(data.password),datetime.now(timezone.utc).isoformat(),role))
            uid=c.execute("SELECT last_insert_rowid()").fetchone()[0]
        except IntegrityError: raise HTTPException(409,"Email already registered")
    raw,exp=create_session(uid); set_session(response,raw,exp); audit(uid,"register",request.client.host if request.client else None)
    return {"id":uid,"email":data.email.lower()}
@router.post("/login")
def login(data:Credentials,request:Request,response:Response):
    enforce_rate_limit(request,settings.rate_limit_per_minute,scope="login",identity=str(data.email))
    with transaction() as c: row=c.execute("SELECT * FROM users WHERE email=?",(data.email.lower(),)).fetchone()
    if not row or row["disabled"] or not verify_password(data.password,row["password_hash"]):
        if row: audit(row["id"],"login_failure",request.client.host if request.client else None)
        raise HTTPException(401,"Invalid credentials")
    with transaction() as c: c.execute("UPDATE users SET last_login=? WHERE id=?",(datetime.now(timezone.utc).isoformat(),row["id"]))
    raw,exp=create_session(row["id"]); set_session(response,raw,exp); audit(row["id"],"login",request.client.host if request.client else None); return {"message":"Logged in"}
@router.post("/logout")
def logout(request:Request,response:Response):
    verify_csrf(request); revoke(request); clear_session_cookie(response); return {"message":"Logged out"}
@router.get("/me")
def me(user=Depends(current_user)): return {"id":user["id"],"email":user["email"]}
@router.post("/change-password")
def change(data:PasswordChange,request:Request,response:Response,user=Depends(current_user)):
    verify_csrf(request); reject_password(data.new_password,user["id"])
    if not verify_password(data.current_password,user["password_hash"]): raise HTTPException(401,"Invalid current password")
    with transaction() as c:c.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(data.new_password),user["id"])); c.execute("UPDATE sessions SET revoked=1 WHERE user_id=?",(user["id"],))
    clear_session_cookie(response); audit(user["id"],"change_password"); return {"message":"Password changed"}
