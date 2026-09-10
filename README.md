# PassGuard

**Auditor y generador de contraseñas de alta entropía, resistentes a la automatización con IA.** Escrito en **Go**, con tres frentes en un solo binario: **TUI** (terminal), **GUI** (ventana Fyne) y **CLI**. Incluye web en GitHub Pages.

> Las máquinas (y las IAs) adivinan contraseñas *cortas, del diccionario, con patrones de teclado y secuencias*. PassGuard penaliza justo eso: solo considera fuerte lo que resiste estimaciones de entropía reales y las listas de filtraciones.

[![CI](https://github.com/Vashuus/passguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Vashuus/passguard/actions) [![MIT](https://img.shields.io/github/license/Vashuus/passguard)](/LICENSE) [![Release](https://img.shields.io/github/v/release/Vashuus/passguard)](https://github.com/Vashuus/passguard/releases)

## Características

- **Auditor de fuerza** inspirado en zxcvbn: entropía (bits), estimación de intentos, tiempo de crack y patrones (palabras del diccionario, l33t `p4ssw0rd`, secuencias `1234`/`abc`, patrones de teclado `qwerty`, repeticiones `aaaaaa`/`abab`).
- **Generador seguro**: claves aleatorias con `crypto/rand` (CSPRNG) + *rejection sampling*: descarta candidatos que el auditor marque débiles. Garantiza ≥1 de cada clase.
- **Frase-pase** memorable estilo diceware (`cobre-uva-trigo-cabra`).
- **Verificación de filtraciones** con API **HaveIBeenPwned** de forma **k-anónima**: solo salen los primeros 5 hex del SHA-1; la contraseña nunca se transmite.
- **Tres interfaces**: TUI en terminal (bubbletea), ventana gráfica (Fyne) y CLI — todo el mismo binario.
- **Web estática** en GitHub Pages (`docs/`) con el mismo modelo, funcionando 100% en el navegador.
- Tema oscuro **Catppuccin Mocha**.

## Descargas

Los binarios los empaqueta GitHub Actions ([workflow](.github/workflows/release.yml)) a partir de un tag `v*`:
- `passguard-<ver>-Linux_x86_64.tar.gz` y `.deb`
- `passguard-<ver>-Windows_x86_64.zip`
- La web se sirve desde `docs/` (GitHub Pages).

## Uso

```sh
passguard                      # TUI interactiva
passguard --gui                # ventana gráfica
passguard check "miClave123"   # auditar en CLI
passguard gen -l 24            # generar (longitud 24)
passguard passphrase -w 5      # frase-pase de 5 palabras
passguard leak "miClave123"    # comprobar filtraciones HIBP
```

### Comandos

| Comando | Descripción |
|---|---|
| `passguard` | TUI interactiva (espacio = HIBP, `g` = generar, `t` = mostrar/ocultar, `q`/`esc` = salir) |
| `passguard --gui` | Ventana nativa Fyne con barra de fuerza en vivo |
| `check "<pw>"` | Entropía, intentos, tiempo de crack, fuerza y patrones |
| `gen [-l 20] [--upper] [--digits] [--symbols] [--similar]` | Generar contraseña CSPRNG |
| `passphrase [-w 4]` | Frase-pase memorable |
| `leak "<pw>"` | ¿Apareció en una filtración? (HIBP k-anónimo) |

## Compilar

```sh
go build ./cmd/passguard     # binario: passguard
ctest  (no aplica aquí)      # pruebas: go test ./...
gofmt -l . && go vet ./...
```

Requisitos: Go ≥ 1.22. La GUI (Fyne) necesita toolchain C y (en Linux) `libgl1-mesa-dev xorg-dev libgtk-3-dev`.

## Pruebas

```sh
go test ./...                    # core: strength, generator, breach, config
go test -race ./internal/strength ./internal/generator
```

## Estructura

```
passguard/
  go.mod / go.sum
  cmd/passguard/
    main.go              Root CLI (cobra) + dispatch TUI/GUI
    runner_tui.go        Interfaz de terminal (bubbletea)
    runner_gui.go        Interfaz gráfica (Fyne, tema Catppuccin)
    breach.go            Helper de cliente HIBP para el CLI
  internal/
    strength/            Motor de fuerza (zxcvbn-like) + diccionarios embebidos
    generator/           CSPRNG + rejection sampling + frase-pase
    breach/              Cliente HIBP k-anónimo
    config/              Config JSON en ~/.config/passguard
  docs/index.html        Página web del proyecto (GitHub Pages)
  .github/workflows/     CI (build+test) y Release (buildeos por OS)
```

## Modelo de entropía

El motor combina cobertura de clases de caracteres, diccionarios de contraseñas filtradas y palabras comunes, sustituciones l33t, secuencias numéricas/alfabéticas, patrones de teclado QWERTY y subcadenas repetidas. El score (0–4) y los "tiempos de crack" siguen las bandas de zxcvbn (guesses vs. ataque offline rápido de ~10¹⁰ guesses/s).

## Limitaciones

- Los diccionarios embebidos son acotados; contraseñas con palabras en otros idiomas pueden puntuar de más. El chequeo HIBP cubre las filtraciones reales conocidas.
- El estimador es un modelo probabilístico, no una garantía de irrompibilidad: la mejor práctica es un **gestor de contraseñas** con claves generadas aleatoriamente y 2FA.

## Seguridad

Ver [SECURITY.md](SECURITY.md). Para reportes, escribe a un canal privado (GitHub Security Advisories) — nunca expongas contraseñas de prueba reales en issues.

## Licencia

MIT — see [LICENSE](LICENSE).