[![GitHub release](https://img.shields.io/github/release/sgaunet/jwt-cli.svg)](https://github.com/sgaunet/jwt-cli/releases/latest)
![GitHub Downloads](https://img.shields.io/github/downloads/sgaunet/jwt-cli/total)
![Coverage](https://raw.githubusercontent.com/wiki/sgaunet/jwt-cli/coverage-badge.svg)
[![Linter](https://github.com/sgaunet/jwt-cli/actions/workflows/linter.yml/badge.svg)](https://github.com/sgaunet/jwt-cli/actions/workflows/linter.yml)
[![Coverage](https://github.com/sgaunet/jwt-cli/actions/workflows/coverage.yml/badge.svg)](https://github.com/sgaunet/jwt-cli/actions/workflows/coverage.yml)
[![Release](https://github.com/sgaunet/jwt-cli/actions/workflows/release.yml/badge.svg)](https://github.com/sgaunet/jwt-cli/actions/workflows/release.yml)
[![GoDoc](https://godoc.org/github.com/sgaunet/jwt-cli?status.svg)](https://godoc.org/github.com/sgaunet/jwt-cli)
[![License](https://img.shields.io/github/license/sgaunet/jwt-cli.svg)](LICENSE)

# jwt-cli

jwt-cli is a utility to encode/decode JWT and PASETO tokens.

```
Usage:
  jwt-cli [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  decode      decode JWT token
  encode      encode JWT token
  genkeys     Print commands to generate cryptographic keys
  help        Help about any command
  paseto      Encode and decode PASETO tokens
  version     Print version information

Flags:
  -h, --help   help for jwt-cli
      --json   output in JSON format

Use "jwt-cli [command] --help" for more information about a command.
```

## Supported JWT methods:

* HS256, HS384, HS512
* ES256, ES384, ES512
* RS256, RS384, RS512

## Supported PASETO versions:

* V2 (local and public)
* V3 (local and public)
* V4 (local and public)

# Demo

![demo](doc/demo.gif)

# Install

## Option 1

* Download the release
* Install the binary in /usr/local/bin 

## Option 2: With brew

```
brew tap sgaunet/homebrew-tools
brew install sgaunet/tools/jwt-cli
```

## Option 3: Docker image

Possibility to copy the binary by using the docker image

```
FROM sgaunet/jwt-cli:latest as jwtcli

FROM ....
COPY --from jwtcli /jwt-cli /usr/bin/jwt-cli
```

# Getting started

This tool will help you encode/decode JWT and PASETO tokens.

```
# encode
$ jwt-cli encode hs512 --payload '{ "email": "myemail@me.com" }' --secret "myAwesomeSecret"
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im15ZW1haWxAbWUuY29tIn0.SE0u1AWrDTHv67PnUALZl8VQ-7rnSXBNDTCVT_Dj12FStO6hL0ak0i4imcUHpWBEh-c5oSc-H90prGQ0oZx6ng
# try to decode with a wrong secret
$ jwt-cli decode hs512 --secret "wrong secret" --token "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im15ZW1haWxAbWUuY29tIn0.SE0u1AWrDTHv67PnUALZl8VQ-7rnSXBNDTCVT_Dj12FStO6hL0ak0i4imcUHpWBEh-c5oSc-H90prGQ0oZx6ng"
signature is invalid
# decode with the good secret
$ jwt-cli decode hs512 --secret "myAwesomeSecret" --token "eyJhbGciOiJIUzUxMiIsInR
5cCI6IkpXVCJ9.eyJlbWFpbCI6Im15ZW1haWxAbWUuY29tIn0.SE0u1AWrDTHv67PnUALZl8VQ-7rnSXBNDTCVT_Dj12FStO6hL0ak0i4imcUHpWBEh-c5oSc-H90prGQ0oZx6ng"
{
  "email": "myemail@me.com"
}
```

> **Note:** `decode` verifies the signature, but does **not** validate the
> time-based claims `exp`, `nbf` and `iat` unless you pass `--validate-claims`.
> A successful decode on its own does **not** mean the token is still valid.

## JWT validation flags

### `--validate-claims`

Rejects a token whose `exp` has passed, whose `nbf` has not yet been reached, or
whose `iat` lies in the future. Off by default, so tokens can always be
inspected regardless of their timing:

```bash
# Expired token: decodes fine by default, contents are still readable
$ jwt-cli decode hs256 --secret "$SECRET" --token "$TOKEN"
{
  "email": "myemail@me.com",
  "exp": 1735689600
}

# The same token, with validation enabled
$ jwt-cli decode hs256 --secret "$SECRET" --token "$TOKEN" --validate-claims
decoding failed: invalid token: failed to parse token: token has invalid claims: token is expired
```

A claim that is absent is never enforced: a token carrying none of the three
still decodes with `--validate-claims`.

On the boundaries, following RFC 7519: a token is expired the moment the clock
reaches `exp`, so `exp` itself is not a valid instant, while `nbf` is valid from
`nbf` inclusive. `decode` and `paseto decode` use the same rule.

If your issuer's clock runs ahead of this machine, a token can be rejected with
`token used before issued` even though it is legitimate. `--clock-skew` is the
remedy.

### `--clock-skew`

Tolerance for clock differences between the issuer and this machine, applied to
`exp`, `nbf` and `iat`. Only meaningful together with `--validate-claims`; the
default is `0`, meaning no tolerance. Takes a Go duration (`30s`, `5m`, `1h`):

```bash
# Accept a token that expired less than five minutes ago
$ jwt-cli decode hs256 --secret "$SECRET" --token "$TOKEN" --validate-claims --clock-skew 5m
```

The value must be zero or positive. A negative duration would narrow the
acceptance window rather than widen it — the opposite of a tolerance — so it is
refused instead of being honoured silently:

```bash
$ jwt-cli decode hs256 --secret "$SECRET" --token "$TOKEN" --validate-claims --clock-skew -5m
Error: --clock-skew must not be negative: got -5m0s
```

### `--allow-weak-secret`

HMAC secrets are checked against the RFC 7518 Section 3.2 minimums — 32 bytes
for HS256, 48 for HS384, 64 for HS512. This flag bypasses that check, and is
intended for testing only:

```bash
$ jwt-cli encode hs256 --secret "short" --payload '{ "email": "myemail@me.com" }'
encoding failed: weak secret: HS256 requires a minimum of 32 bytes (got 5 bytes). Use --allow-weak-secret flag to bypass this check for testing purposes only

$ jwt-cli encode hs256 --secret "short" --payload '{ "email": "myemail@me.com" }' --allow-weak-secret
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im15ZW1haWxAbWUuY29tIn0._zJ610dy5R45NllkjLZMxlYkU8b7UwQ5fxqnq0ZT700
```

The RSA equivalent is `--allow-weak-key`, described under [Create keys](#create-keys).

`--allow-weak-secret` and `--allow-weak-key` apply to both `encode` and
`decode`. `--validate-claims` and `--clock-skew` are `decode` only.

## PASETO Examples

PASETO tokens come in two purposes: `local` (symmetric encryption) and `public`
(asymmetric signing). All three versions are supported — v2 and v4 use Ed25519
keys, v3 uses NIST P-384.

Run `jwt-cli paseto genkeys <version>` to print the exact OpenSSL commands for a
given version.

> **Note:** decoding verifies the token's signature or authentication tag, but
> does **not** validate time-based claims by default — an expired token still
> decodes, so its contents can be inspected. Pass `--validate-claims` to enforce
> them.

### Local (symmetric) tokens

```bash
# Generate a local (symmetric) key
$ openssl rand -hex 32
abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234

# encode PASETO local token (v4 is the default)
$ jwt-cli paseto encode local --key "abcd...1234" --payload '{ "email": "myemail@me.com" }'
v4.local.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# decode PASETO local token
$ jwt-cli paseto decode local --key "abcd...1234" --token "v4.local.xxxxxxxx"
{
  "email": "myemail@me.com"
}

# other versions via --version
$ jwt-cli paseto encode local --version v3 --key "abcd...1234" --payload '{ "email": "myemail@me.com" }'
v3.local.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Public (asymmetric) tokens

```bash
# Show the key generation commands for a version
$ jwt-cli paseto genkeys v4

# Generate an Ed25519 key pair for v2/v4
$ openssl genpkey -algorithm Ed25519 -out paseto-v4-private.pem
$ openssl pkey -in paseto-v4-private.pem -pubout -out paseto-v4-public.pem

# encode PASETO public token
$ jwt-cli paseto encode public --private-key paseto-v4-private.pem --payload '{ "email": "myemail@me.com" }'
v4.public.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# decode with the public key (recommended)
$ jwt-cli paseto decode public --public-key paseto-v4-public.pem --token "v4.public.xxxxxxxx"
{
  "email": "myemail@me.com"
}

# decode with the private key
$ jwt-cli paseto decode public --private-key paseto-v4-private.pem --token "v4.public.xxxxxxxx"
{
  "email": "myemail@me.com"
}
```

For v3, generate a NIST P-384 key pair instead:

```bash
$ openssl ecparam -genkey -name secp384r1 -noout -out paseto-v3-private.pem
$ openssl ec -in paseto-v3-private.pem -pubout -out paseto-v3-public.pem

$ jwt-cli paseto encode public --version v3 --private-key paseto-v3-private.pem --payload '{ "email": "myemail@me.com" }'
v3.public.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Key files may be supplied as PEM (PKCS#8, or SEC 1 for v3) or as raw key bytes.
Password-protected keys are rejected; decrypt them first.

### Registered claims

The registered claims `exp`, `nbf` and `iat` accept either an RFC 3339 timestamp
or a Unix timestamp, and are stored in the RFC 3339 form PASETO requires:

```bash
$ jwt-cli paseto encode local --key "$KEY" --payload '{ "exp": "2030-01-01T00:00:00Z" }'
$ jwt-cli paseto encode local --key "$KEY" --payload '{ "exp": 1893456000 }'
```

### PASETO validation flags

`paseto decode` accepts the same `--validate-claims` and `--clock-skew` flags as
`decode`, with the same defaults, the same `exp` and `nbf` boundaries, and the
same refusal of a negative skew — see
[JWT validation flags](#jwt-validation-flags).

**The two differ in one respect:** `decode` also rejects a future-dated `iat`,
and `paseto decode` does not. PASETO has no `iat` rule, so a token whose `iat`
lies ahead of this machine's clock is rejected by `decode` and accepted by
`paseto decode`.

```bash
# Expired token: decodes fine by default
$ jwt-cli paseto decode local --key "$KEY" --token "$TOKEN"
{
  "email": "myemail@me.com",
  "exp": "2025-01-01T00:00:00Z"
}

# The same token, with validation enabled
$ jwt-cli paseto decode local --key "$KEY" --token "$TOKEN" --validate-claims
decoding failed: claims validation failed: token has expired (exp 2025-01-01T00:00:00Z)

# Accept a token that expired less than five minutes ago
$ jwt-cli paseto decode local --key "$KEY" --token "$TOKEN" --validate-claims --clock-skew 5m
```

Only `exp` and `nbf` are enforced, and only when the claim is present: a token
carrying neither still decodes with `--validate-claims`. `iat` and `aud` are
never enforced here — unlike the JWT `decode` path, which does reject a
future-dated `iat`.

### JSON output

Like the JWT commands, every PASETO `encode` and `decode` command supports
`--json` for programmatic use:

```bash
$ jwt-cli paseto decode local --json --key "$KEY" --token "$TOKEN"
{
  "success": true,
  "claims": {
    "email": "myemail@me.com"
  }
}
```

`paseto genkeys` prints shell commands for you to run and ignores `--json`, as
`genkeys` does.

If a decoded token carries a footer — PASETO authenticates it but keeps it
outside the claim set — it is reported alongside the claims:

```bash
$ jwt-cli paseto decode local --key "$KEY" --token "$TOKEN_WITH_FOOTER"
{
  "email": "myemail@me.com"
}
footer: {"kid":"key-1"}
```

# Output and exit codes

**Exit code 0 on success, 1 on any failure**, in both output modes. That holds
for every failure class: an unknown command or flag, a mistyped algorithm, a
trailing argument, a missing or unreadable or oversized or encrypted key, a weak
secret or key, a malformed payload, a bad signature, an algorithm mismatch, and
claims validation.

In the default mode, results go to **stdout** and errors to **stderr**, so
`jwt-cli encode … 2>/dev/null` yields a bare token and nothing else.

With `--json`, one of three envelopes goes to **stdout** — including on failure,
so a caller can parse a single stream:

```json
{ "success": true,  "token": "eyJhbGci..." }
{ "success": true,  "claims": { "email": "myemail@me.com" } }
{ "success": false, "error": "decoding failed: invalid token: ..." }
```

`genkeys` and `paseto genkeys` emit their recipe under a `data` key instead. Note
that their plain-text output is meant to be piped into a shell
(`eval "$(jwt-cli genkeys rs256)"`), so prefer that form in scripts.

Two deliberate exceptions:

- `version --json` emits a bare `{"version": …}` object rather than the envelope,
  since build metadata is not a token result. It also accepts `-j`, which no
  other command does.
- `--help` output is plain text in both modes.

# Shell Completion

jwt-cli supports shell completion for bash, zsh, fish, and PowerShell. This enables TAB completion for commands, subcommands, and flags.

## Installation

### Bash

**On macOS (using Homebrew):**
```bash
jwt-cli completion bash > $(brew --prefix)/etc/bash_completion.d/jwt-cli
source ~/.bashrc
```

**On Linux:**
```bash
sudo jwt-cli completion bash > /etc/bash_completion.d/jwt-cli
source ~/.bashrc
```

### Zsh

```bash
# Create completions directory if it doesn't exist
mkdir -p ~/.zsh/completions

# Generate completion file
jwt-cli completion zsh > ~/.zsh/completions/_jwt-cli

# Add to .zshrc if not already present:
# fpath=(~/.zsh/completions $fpath)
# autoload -Uz compinit && compinit
```

### Fish

```bash
jwt-cli completion fish > ~/.config/fish/completions/jwt-cli.fish
```

### PowerShell

```powershell
# For current session
jwt-cli completion powershell | Out-String | Invoke-Expression

# For persistent installation, add to your PowerShell profile:
jwt-cli completion powershell >> $PROFILE
```

## Usage Examples

After installation and restarting your shell:

```bash
jwt-cli <TAB>              # Shows: encode, decode, genkeys, version, help
jwt-cli encode <TAB>       # Shows: hs256, hs384, hs512, rs256, rs384, rs512, es256, es384, es512
jwt-cli encode hs256 -<TAB> # Shows available flags
jwt-cli decode rs256 --private-key <TAB>  # Shows .pem and .key files
```

## Troubleshooting

If completion doesn't work:
1. Verify jwt-cli is in your PATH: `which jwt-cli`
2. Restart your shell or open a new terminal window
3. For Zsh, ensure fpath includes your completions directory
4. Check that completion files are in the correct location

For more information: `jwt-cli completion --help`

# Development

This project is using :

* golang — the required version is declared in [go.mod](go.mod), and the exact
  toolchain used by CI is pinned in [mise.toml](mise.toml)
* [task for development](https://taskfile.dev/#/)
* docker
* [docker buildx](https://github.com/docker/buildx)
* docker manifest
* [goreleaser](https://goreleaser.com/)
* [vhs](https://github.com/charmbracelet/vhs) — records the demo GIF above

The docker image is only created to simplify the copy of jwt-cli in another docker image.

The demo GIF is scripted in [doc/demo.tape](doc/demo.tape). Regenerate it with `task demo`,
which builds the binary first and then renders `doc/demo.gif`. Rendering also needs `ttyd`
and `ffmpeg` on the PATH.


# Create keys

RSA keys must be at least 2048 bits. The `encode`/`decode` commands reject a
shorter key; pass `--allow-weak-key` to accept one for testing only. ECDSA key
sizes are fixed by the curve the algorithm names, so the `es*` commands have no
`--allow-weak-key` flag at all and reject it as an unknown flag.

## What the key flags accept

**Password-protected keys are rejected.** An encrypted key is a valid PEM block
whose contents are ciphertext, so it cannot be parsed without the password, which
jwt-cli does not prompt for. Decrypt it first — the error names the command to
use, matching the key's own encoding:

```bash
$ jwt-cli encode rs256 --private-key encrypted.pem --payload '{ "email": "myemail@me.com" }'
encoding failed: invalid key: key file is password-protected: PKCS#8 "ENCRYPTED PRIVATE KEY" block. Decrypt it first, e.g. openssl pkey -in key.pem -out key.decrypted.pem
```

**`--public-key` also accepts an X.509 certificate in PEM form**, lifting the
public key out of it. Be aware that **no certificate validation of any kind is
performed**: the validity window, issuer, chain and key usage are all ignored, so
an expired or self-signed certificate verifies tokens exactly as a bare public
key would. If those properties matter to you, check them separately.

Key files are read under a 1 MiB size bound, so pointing a key flag at a large
file or an endless device fails immediately rather than exhausting memory.

## RS256

```
ssh-keygen -t rsa -b 4096 -E SHA256 -m PEM -P "" -f RS256-private.pem
openssl rsa -in RS256-private.pem -pubout -outform PEM -out RS256-public.pem
```

## RS384

```
ssh-keygen -t rsa -b 4096 -E SHA384 -m PEM -P "" -f RS384-private.pem
openssl rsa -in RS384-private.pem -pubout -outform PEM -out RS384-public.pem
```

## RS512

```
ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P "" -f RS512-private.pem
openssl rsa -in RS512-private.pem -pubout -outform PEM -out RS512-public.pem
```

## ES256

```
openssl ecparam -genkey -name prime256v1  -noout -out ES256-private.pem
openssl ec -in ES256-private.pem -pubout -out ES256-public.pem
```

## ES384

```
openssl ecparam -name secp384r1 -genkey -noout -out ES384-private.pem
openssl ec -in ES384-private.pem -pubout -out ES384-public.pem
```

## ES512

```
openssl ecparam -genkey -name secp521r1 -noout -out ES512-private.pem
openssl ec -in ES512-private.pem -pubout -out ES512-public.pem
```