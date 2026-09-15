from datetime import datetime,timezone
from app.database.connection import transaction
def audit(user_id,event,ip=None):
    with transaction() as c:c.execute("INSERT INTO audit_logs(user_id,event,ip,created_at) VALUES(?,?,?,?)",(user_id,event,ip,datetime.now(timezone.utc).isoformat()))
