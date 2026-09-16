from app.security.hashing import hash_password, verify_password
from app.services.password_policy import validate_password

def validate_credentials(password: str) -> None:
    errors = validate_password(password)
    if errors:
        raise ValueError(errors)

def hash_new_password(password: str) -> str:
    validate_credentials(password)
    return hash_password(password)

def check_password(password: str, password_hash: str) -> bool:
    return verify_password(password, password_hash)