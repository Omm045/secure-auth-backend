from datetime import datetime,timezone
import json
from app.database.connection import transaction
def audit(user_id,event,ip=None,metadata=None):
    with transaction() as c:
        c.execute("INSERT INTO audit_logs(user_id,event,ip,metadata,created_at) VALUES(?,?,?,?,?)",
                  (user_id,event,ip,json.dumps(metadata, sort_keys=True) if metadata else None,
                   datetime.now(timezone.utc).isoformat()))
