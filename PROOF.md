# Breach-check proof

Passwords must reach the backend over HTTPS so the server can validate and
hash them; that transport requirement is unavoidable. After receipt, the
breach-check request uses only the first five characters of the SHA-1 digest
(HIBP k-anonymity). It never sends the password or full digest outside the
backend. `tests/test_no_plaintext_leak.py` mocks the outbound HTTP client and
asserts both properties. Reset and verification links use fragments; the
frontend removes the fragment with `history.replaceState` before submitting a
single-use token in a POST body.
