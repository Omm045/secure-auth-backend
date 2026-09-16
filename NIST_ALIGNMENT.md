# NIST SP 800-63B alignment

| Requirement | Implementation |
|---|---|
| Minimum length | 15 characters for single-factor passwords (`password_policy.py`) |
| Composition rules | None; arbitrary printable passwords are accepted |
| Compromised-password screening | HIBP k-anonymity plus local compromised list |
| Forced rotation | None; reset/change is user initiated |
| Failed attempts | IP and account-scoped, failed-only limits |
| Storage | Argon2id salted password hashes |

The service does not currently implement a dedicated authenticator
management UI, recovery-code enrollment, or a configurable verifier retry
counter policy. Those are remaining deployment-level gaps rather than claims
of full NIST conformance.
