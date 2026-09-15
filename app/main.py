from fastapi import FastAPI,Request,Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.database.connection import init_db
from app.api.auth import router as auth_router
from app.api.password import router as password_router
from app.api.admin import router as admin_router
from app.security.csrf import csrf_token
app=FastAPI(title="Secure Auth API",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_origins,allow_credentials=True,allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type","X-CSRF-Token"])
@app.on_event("startup")
def startup(): init_db()
@app.middleware("http")
async def security_headers(request:Request,call_next):
    response=await call_next(request);     response.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'none'","Permissions-Policy":"geolocation=(), microphone=(), camera=()","Strict-Transport-Security":"max-age=31536000; includeSubDomains"}); return response
@app.get("/health")
def health(): return {"status":"ok"}
@app.get("/csrf")
def csrf(response:Response):
    value=csrf_token(); response.set_cookie("csrf_token",value,httponly=False,secure=settings.session_cookie_secure,samesite="lax"); return {"csrf_token":value}
app.include_router(auth_router); app.include_router(password_router); app.include_router(admin_router)
