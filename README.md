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
Tool to encode/decode JWT and PASETO tokens

Usage:
  jwt-cli [command]

Available Commands:
  decode      decode JWT token
  encode      encode JWT token
  genkeys     print commands example to generate keys for ES256, ES384, ES512, RS256, RS384, RS512
  help        Help about any command
  paseto      PASETO token operations
  version     print version of jwt-cli

Flags:
  -h, --help   help for jwt-cli

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

## PASETO Examples

PASETO tokens come in two purposes: `local` (symmetric encryption) and `public`
(asymmetric signing). All three versions are supported — v2 and v4 use Ed25519
keys, v3 uses NIST P-384.

Run `jwt-cli paseto genkeys <version>` to print the exact OpenSSL commands for a
given version.

> **Note:** decoding verifies the token's signature or authentication tag, but
> does **not** validate time-based claims — an expired token still decodes, so
> its contents can be inspected.

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

### Registered claims

The registered claims `exp`, `nbf` and `iat` accept either an RFC 3339 timestamp
or a Unix timestamp, and are stored in the RFC 3339 form PASETO requires:

```bash
$ jwt-cli paseto encode local --key "$KEY" --payload '{ "exp": "2030-01-01T00:00:00Z" }'
$ jwt-cli paseto encode local --key "$KEY" --payload '{ "exp": 1893456000 }'
```

### JSON output

Like the JWT commands, every PASETO command supports `--json` for programmatic use:

```bash
$ jwt-cli paseto decode local --json --key "$KEY" --token "$TOKEN"
{
  "success": true,
  "claims": {
    "email": "myemail@me.com"
  }
}
```

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

* golang 1.23+
* [task for development](https://taskfile.dev/#/)
* docker
* [docker buildx](https://github.com/docker/buildx)
* docker manifest
* [goreleaser](https://goreleaser.com/)

The docker image is only created to simplify the copy of jwt-cli in another docker image.


# Create keys

RSA keys must be at least 2048 bits. The `encode`/`decode` commands reject a
shorter key; pass `--allow-weak-key` to accept one for testing only.

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