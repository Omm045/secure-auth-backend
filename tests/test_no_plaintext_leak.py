from app.services.breach_checker import BreachChecker

def test_breach_checker_sends_only_sha1_prefix():
    password = "never-send-this-password"
    calls = []
    class Response:
        text = ""
        def raise_for_status(self): pass
    class Client:
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return Response()
    BreachChecker(client=Client(), base_url="https://hibp.test/").is_breached(password)
    transmitted = calls[0][0].split("/")[-1]
    assert len(transmitted) == 5
    assert password not in transmitted
    assert transmitted != __import__("hashlib").sha1(password.encode()).hexdigest().upper()
