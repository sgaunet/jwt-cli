[![Go Report Card](https://goreportcard.com/badge/github.com/sgaunet/jwt-cli)](https://goreportcard.com/report/github.com/sgaunet/jwt-cli)
[![GitHub release](https://img.shields.io/github/release/sgaunet/jwt-cli.svg)](https://github.com/sgaunet/jwt-cli/releases/latest)
![GitHub Downloads](https://img.shields.io/github/downloads/sgaunet/jwt-cli/total)
![Coverage](https://raw.githubusercontent.com/wiki/sgaunet/jwt-cli/coverage-badge.svg)
[![Linter](https://github.com/sgaunet/jwt-cli/actions/workflows/linter.yml/badge.svg)](https://github.com/sgaunet/jwt-cli/actions/workflows/linter.yml)
[![Coverage](https://github.com/sgaunet/jwt-cli/actions/workflows/coverage.yml/badge.svg)](https://github.com/sgaunet/jwt-cli/actions/workflows/coverage.yml)
[![Release](https://github.com/sgaunet/jwt-cli/actions/workflows/release.yml/badge.svg)](https://github.com/sgaunet/jwt-cli/actions/workflows/release.yml)
[![GoDoc](https://godoc.org/github.com/sgaunet/jwt-cli?status.svg)](https://godoc.org/github.com/sgaunet/jwt-cli)
[![License](https://img.shields.io/github/license/sgaunet/jwt-cli.svg)](LICENSE)

# jwt-cli

jwt-cli is a utility to encode/decode JWT token.

```
Tool to encode/decode JWT token

Usage:
  jwt-cli [command]

Available Commands:
  decode      decode JWT token
  encode      encode JWT token
  genkeys     print commands example to generate keys for ES256, ES384, ES512, RS256, RS384, RS512
  help        Help about any command
  version     print version of jwt-cli

Flags:
  -h, --help   help for jwt-cli

Use "jwt-cli [command] --help" for more information about a command.
```

Supported methods are actually:

* HS256
* HS384
* HS512
* ES256
* ES384
* ES512
* RS256
* RS384
* RS512

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

Quite easy, this tool will help you to encode/decode JWT tokens.

```
# encode
$ jwt-cli encode hs512 --p '{ "email": "myemail@me.com" }' --s "myAwesomeSecret"
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im15ZW1haWxAbWUuY29tIn0.SE0u1AWrDTHv67PnUALZl8VQ-7rnSXBNDTCVT_Dj12FStO6hL0ak0i4imcUHpWBEh-c5oSc-H90prGQ0oZx6ng
# try to decode with a wrong secret
$ jwt-cli decode hs512 --s "wrong secret" --t "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im15ZW1haWxAbWUuY29tIn0.SE0u1AWrDTHv67PnUALZl8VQ-7rnSXBNDTCVT_Dj12FStO6hL0ak0i4imcUHpWBEh-c5oSc-H90prGQ0oZx6ng"
signature is invalid
# decode with the good secret
$ jwt-cli decode hs512 --s "myAwesomeSecret" --t "eyJhbGciOiJIUzUxMiIsInR
5cCI6IkpXVCJ9.eyJlbWFpbCI6Im15ZW1haWxAbWUuY29tIn0.SE0u1AWrDTHv67PnUALZl8VQ-7rnSXBNDTCVT_Dj12FStO6hL0ak0i4imcUHpWBEh-c5oSc-H90prGQ0oZx6ng"
{
  "email": "myemail@me.com"
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
jwt-cli decode rs256 --private-key-file <TAB>  # Shows .pem and .key files
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