COMMON={"password","password123","12345678","qwertyui","letmein","admin123"}
def validate_password(password:str)->list[str]:
    errors=[]
    if len(password)<15: errors.append("Password must be at least 15 characters")
    if len(password)>128: errors.append("Password must be at most 128 characters")
    if password.lower() in COMMON: errors.append("Password is too common")
    return errors
def enforce_password(password:str):
    errors=validate_password(password)
    if errors: raise ValueError("; ".join(errors))

def is_password_compromised(password: str, blocklist=None) -> bool:
    return password.lower() in (blocklist if blocklist is not None else COMMON)

def check_password_policy(password: str) -> tuple[bool, list[str]]:
    errors = validate_password(password)
    return not errors, errors
