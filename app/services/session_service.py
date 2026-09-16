from datetime import datetime,timedelta,timezone
from fastapi import HTTPException,Request
from app.database.connection import transaction
from app.security.tokens import token,token_hash
from app.config import settings

def create_session(user_id):
    raw=token(); now=datetime.now(timezone.utc); exp=now+timedelta(minutes=settings.access_token_expire_minutes)
    with transaction() as c:
        c.execute("INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at,revoked) VALUES(?,?,?,?,?,FALSE)",
                  (token(),user_id,token_hash(raw),exp.isoformat(),now.isoformat()))
    return raw,exp

def current_user(request:Request):
    cookie_name = "__Host-session" if settings.environment == "production" else "session"
    raw=request.cookies.get(cookie_name) or request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not raw: raise HTTPException(401,"Authentication required")
    with transaction() as c:
        row=c.execute("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.revoked=FALSE AND s.expires_at>?",(token_hash(raw),datetime.now(timezone.utc).isoformat())).fetchone()
    if not row or row["disabled"]: raise HTTPException(401,"Authentication required")
    return row

def revoke(request):
    cookie_name = "__Host-session" if settings.environment == "production" else "session"
    raw=request.cookies.get(cookie_name) or request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if raw:
        with transaction() as c:c.execute("UPDATE sessions SET revoked=TRUE WHERE token_hash=?",(token_hash(raw),))
