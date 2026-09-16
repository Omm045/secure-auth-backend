from fastapi import FastAPI,Request,Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from app.config import settings
from app.database.connection import init_db
from app.api.auth import router as auth_router
from app.api.password import router as password_router
from app.api.admin import router as admin_router
from app.security.csrf import csrf_token
from app.security.cookies import set_csrf_cookie
from app.logging_config import configure_logging, request_id
import logging
app=FastAPI(title="Secure Auth API",version="1.0.0")
app.mount("/app", StaticFiles(directory="frontend", html=True), name="frontend")
configure_logging()
logger = logging.getLogger("secure_auth")
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_origins,allow_credentials=True,allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type","X-CSRF-Token"])
@app.on_event("startup")
def startup():
    init_db()
    if settings.sentry_dsn:
        try:
            import sentry_sdk
            sentry_sdk.init(dsn=settings.sentry_dsn)
        except ImportError:
            logger.warning("SENTRY_DSN is set but sentry-sdk is not installed")
@app.middleware("http")
async def security_headers(request:Request,call_next):
    correlation_id = request.headers.get("X-Request-ID") or request_id()
    content_length = request.headers.get("content-length")
    try:
        oversized = content_length is not None and int(content_length) > 1_048_576
    except ValueError:
        oversized = True
    if oversized:
        response = JSONResponse({"detail": "Request body too large"}, status_code=413)
        response.headers["X-Request-ID"] = correlation_id
        return response
    try:
        response=await call_next(request)
    except Exception:
        logger.exception("Unhandled application exception", extra={"request_id": correlation_id})
        response = JSONResponse({"detail": "Internal server error"}, status_code=500)
    response.headers["X-Request-ID"] = correlation_id
    if response.status_code >= 500:
        logger.error("5xx response", extra={"request_id": correlation_id})
    response.headers.update({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'","Permissions-Policy":"geolocation=(), microphone=(), camera=()"})
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
@app.get("/health")
def health(): return {"status":"ok"}
@app.get("/ready")
def ready():
    from app.database.connection import transaction
    try:
        with transaction() as connection:
            connection.execute("SELECT 1")
        return {"status":"ready"}
    except Exception:
        return JSONResponse({"status":"not_ready"}, status_code=503)
@app.get("/csrf")
def csrf(response:Response):
    value=csrf_token(); set_csrf_cookie(response, value); return {"csrf_token":value}
app.include_router(auth_router); app.include_router(password_router); app.include_router(admin_router)
