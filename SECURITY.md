# Security policy

Report suspected vulnerabilities privately to the project maintainers. Do not
include credentials, reset tokens, or other sensitive data in an issue. Please
include reproduction steps, affected versions, and impact. Security fixes
should be coordinated before public disclosure.

The application treats public registration as unprivileged and requires
verified identity for administrator endpoints. Passwords use a 15-character
minimum for this password-only service, HIBP checks transmit only a five
character SHA-1 prefix, and reset/verification tokens are hashed at rest and
transported from URL fragments into POST bodies by the bundled frontend.
