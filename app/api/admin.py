import csv
from pathlib import Path
from fastapi import APIRouter,Depends,HTTPException,Request
from app.services.session_service import current_user
from app.database.connection import transaction
from app.services.breach_checker import BreachChecker
from app.security.rate_limit import enforce_rate_limit
router=APIRouter(prefix="/admin",tags=["admin"])
def require_admin(user=Depends(current_user)):
    if user["role"] != "admin": raise HTTPException(403,"Admin access required")
    return user
@router.get("/stats")
def stats(user=Depends(require_admin)):
    with transaction() as c:
        users=c.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        logs=c.execute("SELECT COUNT(*) AS count FROM audit_logs").fetchone()["count"]
        breaches=c.execute("SELECT COUNT(*) AS count FROM audit_logs WHERE event='password_breach'").fetchone()["count"]
    return {"users":users,"audit_events":logs,"password_breaches":breaches}

@router.get("/breach-report")
def breach_report(request: Request, user=Depends(require_admin)):
    enforce_rate_limit(request, 2, scope="breach-report")
    checker = BreachChecker()
    accounts = []
    sample_path = Path(__file__).parents[1] / "data" / "sample_accounts.csv"
    for account in csv.DictReader(sample_path.open(newline="", encoding="utf-8")):
        accounts.append({"email": account["email"], "breached": checker.is_breached(account["password"])})
    breached = sum(item["breached"] for item in accounts)
    percentage = round((breached / len(accounts)) * 100, 2) if accounts else 0
    return {"summary": f"{percentage}% of test accounts use a breached password",
            "accounts": accounts}
