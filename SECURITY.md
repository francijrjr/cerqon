# Security Policy

## CERQON: Defensive Security & Privacy Guarantee

CERQON is built from the ground up on the principle of **Local-First Defensive Security**:

- **Offline Analysis**: All parsing, scanning, rule evaluation, and score calculation run strictly locally on your machine.
- **Zero Telemetry**: No telemetry, analytics, or behavioral tracking is gathered or transmitted.
- **Zero Cloud Upload**: Scanned files, configuration paths, and secrets are never sent to external servers.
- **Safe Secret Handling**: Discovered credentials are automatically masked in memory before rendering or saving (`sk-****...****`). CERQON never prints or stores full secret tokens.
- **No Active Exploitation**: The scanner performs static analysis only. It never attempts active payload injection, network penetration, or credential stuffing.

## Reporting a Vulnerability

If you discover a security vulnerability within CERQON itself, please report it privately:

- **Email**: `security@cerqon.io` (or create a private GitHub Security Advisory)
- Do not file public issues for zero-day vulnerabilities.
- Provide full reproduction steps, affected versions, and potential impact.

We aim to acknowledge reports within 48 hours and provide patches within 7 business days.
