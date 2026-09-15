from app.services.breach_checker import BreachChecker
import hashlib
class Resp:
    def __init__(self,text): self.text=text
    def raise_for_status(self): pass
class Client:
    def __init__(self,text): self.text=text; self.url=None
    def get(self,url,headers): self.url=url; return Resp(self.text)
def test_hibp_prefix_only():
    pw='abcdefgh'; digest=hashlib.sha1(pw.encode()).hexdigest().upper(); c=Client(digest[5:]+':3\n')
    assert BreachChecker(c,'https://example/').is_breached(pw)
    assert c.url == 'https://example/'+digest[:5]
