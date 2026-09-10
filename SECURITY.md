# Security Policy

## Al reportar una vulnerabilidad

**NO abras un issue público** con contraseñas o hashes de prueba reales. Usa
[GitHub Security Advisories](https://github.com/Vashuus/passguard/security/advisories/new)
o contacta al mantenedor por un canal privado.

## Alcance

- `internal/strength` — calidad de la estimación de entropía.
- `internal/generator` — uso correcto de CSPRNG (`crypto/rand`).
- `internal/breach` — garantía k-anónima (que la contraseña nunca salga del host).
- `cmd/passguard` — manejo de entrada y de la CLI.
- `docs/` — que la web jamás envíe la contraseña en claro.

## Compromisos

Este proyecto **nunca** transmite tu contraseña; la web y el CLI solo envían,
en el caso del chequeo de filtraciones, el prefijo truncado del hash SHA-1.
Cualquier cambio que rompa esa promesa se considera una vulnerabilidad de
severidad crítica.