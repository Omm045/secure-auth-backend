from app.services.breach_checker import BreachChecker
import hashlib
class Resp:
    def __init__(self,text): self.text=text
    def raise_for_status(self): pass
class Client:
    def __init__(self,text, error=None): self.text=text; self.url=None; self.error=error
    def get(self,url,headers): self.url=url; return Resp(self.text)
def test_hibp_prefix_only():
    pw='correct horse battery staple'; digest=hashlib.sha1(pw.encode()).hexdigest().upper(); c=Client(digest[5:]+':3\n')
    assert BreachChecker(c,'https://example/').is_breached(pw)
    assert c.url == 'https://example/'+digest[:5]

def test_hibp_zero_count_is_not_a_breach():
    pw = "a sufficiently long password"
    digest = hashlib.sha1(pw.encode()).hexdigest().upper()
    assert not BreachChecker(Client(digest[5:] + ":0\n"), "https://example/").is_breached(pw)

def test_hibp_negative_malformed_and_api_failure():
    pw = "another sufficiently long password"
    digest = hashlib.sha1(pw.encode()).hexdigest().upper()
    assert not BreachChecker(Client("not-a-record\n" + digest[5:] + ":oops\n"), "https://example/").is_breached(pw)

    class FailingClient:
        def get(self, *args, **kwargs):
            raise TimeoutError("timeout")
    import pytest
    with pytest.raises(TimeoutError):
        BreachChecker(FailingClient(), "https://example/").is_breached(pw)
