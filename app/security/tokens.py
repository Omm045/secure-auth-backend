import hashlib,secrets

def token(): return secrets.token_urlsafe(32)
def token_hash(value): return hashlib.sha256(value.encode()).hexdigest()
