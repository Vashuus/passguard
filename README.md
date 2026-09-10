# PassGuard

[![CI](https://github.com/Vashuus/passguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Vashuus/passguard/actions)
[![MIT](https://img.shields.io/github/license/Vashuus/passguard)](/LICENSE)
[![Release](https://img.shields.io/github/v/release/Vashuus/passguard)](https://github.com/Vashuus/passguard/releases)
[![Web](https://img.shields.io/badge/web-GitHub%20Pages-89b4fa)](https://vashuus.github.io/passguard/)

**AI-resistant password auditor & generator.** Same engine behind four
fronts: **TUI**, **GUI**, **CLI** and a **static web app**.

> Attackers (and AI tools) don't brute-force your password—they *predict* it: short
> strings, dictionary words, keyboard patterns, l33t speak and breaches they already
> own. PassGuard scores exactly that: only high-entropy, pattern-free passwords with
> no leaked history count as strong.

Live demo (works 100% in your browser, nothing is sent to a server):

**Web: https://vashuus.github.io/passguard/**

---

## Features

- **Strength auditing** (zxcvbn-inspired): entropy (bits), guess count, crack-time
  and pattern detection — dictionary words, l33t (`p4ssw0rd`), digit/alpha
  sequences (`1234`, `abcdef`), QWERTY runs (`qwerty`), repetitions (`aaaaaa`/`abab`).
- **Secure generator**: cryptographically random keys (`crypto/rand` CSPRNG) with
  **rejection sampling** — candidates the auditor flags as weak are discarded, and
  each requested character class is guaranteed.
- **Memorable passphrases** (diceware-style): `cobre-uva-trigo-cabra`.
- **Breach check** via HaveIBeenPwned, **k-anonymously**: only the first 5 hex chars
  of the SHA-1 hash leave your machine — the password itself never travels.
- **Four interfaces, one binary**: TUI (bubbletea), GUI (Fyne), CLI (cobra) and the
  web app in `docs/`.
- **Catppuccin Mocha** dark theme.
- Tests with `-race`, CI + multi-OS release pipelines.

## Usage

```sh
passguard                      # interactive TUI
passguard --gui                # native GUI window
passguard check "p@ssw0rd123"  # audit a password in the terminal
passguard gen -l 24            # generate one (length 24)
passguard passphrase -w 5      # 5-word passphrase
passguard leak "p@ssw0rd123"   # has it leaked? (k-anonymous HIBP)
```

### Commands

| Command | Description |
|---|---|
| `passguard` | TUI (space = HIBP check, `g` = generate, `t` = reveal/hide, `q`/`esc` = quit) |
| `passguard --gui` | Fyne window with a live strength bar |
| `check "<pw>"` | Entropy, guesses, crack time, strength score and found patterns |
| `gen [-l 20] [--upper] [--digits] [--symbols] [--similar]` | CSPRNG-password |
| `passphrase [-w 4]` | Memorable passphrase |
| `leak "<pw>"` | Did it appear in a known breach? (HIBP, k-anonymous) |

## Install & build

```sh
go build ./cmd/passguard        # binary: passguard
go test ./...                   # unit tests (core)
go test -race ./internal/strength ./internal/generator
gofmt -l . && go vet ./...
```

Requirements: Go ≥ 1.22. The Fyne GUI needs a C toolchain and on Linux
`libgl1-mesa-dev xorg-dev libgtk-3-dev`.

Prebuilt binaries are produced by the [release workflow](.github/workflows/release.yml)
for every `v*` tag: Linux (`tar.gz`, `.deb`), Windows (`zip`) and macOS (`dmg`).

## Project structure

```
passguard/
  go.mod / go.sum
  cmd/passguard/
    main.go              Cobra root (CLI) + TUI/GUI dispatch
    runner_tui.go        Terminal UI (bubbletea)
    runner_gui.go        Native GUI (Fyne, Catppuccin theme)
    breach.go            HIBP client helper
  internal/
    strength/            Entropy engine (zxcvbn-like) + embedded dictionaries
    generator/           CSPRNG + rejection sampling + passphrases
    breach/              k-anonymous HIBP client
    config/              JSON config at ~/.config/passguard
  docs/index.html        GitHub Pages web app
  .github/workflows/     CI (build+test) and Release (per-OS binaries)
  res/
    icon.svg             App icon
```

## Entropy model

The engine combines character-class coverage with embedded dictionaries of leaked /
common passwords, English words, l33t substitutions, numeric and alphabetic
sequences, QWERTY keyboard runs and repeated substrings. The `0–4` score and
crack-time bands follow zxcvbn's guess-count thresholds (vs. a fast offline attack
at ~10¹⁰ guesses/s).

## Limitations

- Embedded dictionaries are intentionally bounded; words from other languages may
  be over-scored. The HIBP check covers real known breaches.
- Entropy estimation is a probabilistic model, not a guarantee of uncrackability.
  Best practice: use a **password manager** with randomly generated keys + 2FA.

## Security

Read [SECURITY.md](SECURITY.md). This project **never transmits your password**;
only the SHA-1 prefix goes out for the breach check. Report issues privately via
GitHub Security Advisories.

## License

MIT — see [LICENSE](LICENSE).
