from app.services.password_policy import validate_password,is_password_compromised

def test_policy_length_only():
    assert validate_password('abcdefgh') == []
    assert 'at least 8' in validate_password('short')[0]
    assert is_password_compromised('password')
