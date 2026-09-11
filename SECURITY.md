# Security Policy

## Reporting a vulnerability

**Do NOT open a public issue** containing real credentials or test hashes. Use
[GitHub Security Advisories](https://github.com/Vashuus/passguard/security/advisories/new)
or contact the maintainer through a private channel.

## Scope

- `internal/strength` — quality of the entropy estimation.
- `internal/generator` — correct use of the CSPRNG (`crypto/rand`).
- `internal/breach` — k-anonymity guarantee (the password never leaves the host).
- `internal/clipboard` — provisioning the system clipboard without exposing secrets.
- `cmd/passguard` — input handling and the CLI/GUI/TUI layer.
- `docs/` — the web app must never transmit the plaintext password.

## Commitments

This project **never transmits your password**; for the breach check the web and
CLI only send the truncated SHA-1 hash prefix. Any change that breaks that promise
is considered a critical-severity vulnerability.