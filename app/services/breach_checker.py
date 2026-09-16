import hashlib
import httpx
class BreachChecker:
    def __init__(self,client=None,base_url=None): 
        from app.config import settings
        self.client=client or httpx.Client(timeout=5); self.base_url=base_url or settings.hibp_api_url
    def is_breached(self,password:str)->bool:
        digest=hashlib.sha1(password.encode()).hexdigest().upper(); prefix,suffix=digest[:5],digest[5:]
        response=self.client.get(self.base_url+prefix,headers={"Add-Padding":"true"}); response.raise_for_status()
        for line in response.text.splitlines():
            if ":" not in line:
                continue
            candidate, count = line.split(":", 1)
            try:
                if candidate.strip().upper() == suffix and int(count.strip()) > 0:
                    return True
            except ValueError:
                continue
        return False

HIBPChecker = BreachChecker
