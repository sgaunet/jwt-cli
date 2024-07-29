[![Go Report Card](https://goreportcard.com/badge/github.com/sgaunet/jwt-cli)](https://goreportcard.com/report/github.com/sgaunet/jwt-cli)
[![GitHub release](https://img.shields.io/github/release/sgaunet/jwt-cli.svg)](https://github.com/sgaunet/jwt-cli/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/sgaunet/jwt-cli)](https://goreportcard.com/report/github.com/sgaunet/jwt-cli)
![GitHub Downloads](https://img.shields.io/github/downloads/sgaunet/jwt-cli/total)
[![Maintainability](https://api.codeclimate.com/v1/badges/f5a67145b82f28869435/maintainability)](https://codeclimate.com/github/sgaunet/jwt-cli/maintainability)
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
brew tap sgaunet/tools
brew install jwt-cli
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

# Development

This project is using :

* golang 1.19+
* [task for development](https://taskfile.dev/#/)
* docker
* [docker buildx](https://github.com/docker/buildx)
* docker manifest
* [goreleaser](https://goreleaser.com/)

The docker image is only created to simplify the copy of jwt-cli in another docker image.


# Create keys

## RS256

```
ssh-keygen -t rsa -b 4096 -E SHA256 -m PEM -P "" -f RS256.key
openssl rsa -in RS256.key -pubout -outform PEM -out RS256.key.pub
```

## RS384

```
ssh-keygen -t rsa -b 4096 -E SHA384 -m PEM -P "" -f RS384.key
openssl rsa -in RS384.key -pubout -outform PEM -out RS384.key.pub
```

## RS512

```
ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P "" -f RS512.key
openssl rsa -in RS512.key -pubout -outform PEM -out RS512.key.pub
```

## ES256

```
openssl ecparam -genkey -name prime256v1  -noout -out ecdsa-p256-private.pem
openssl ec -in ecdsa-p256-private.pem -pubout -out ecdsa-p256-public.pem 
```

## ES384

```
openssl ecparam -name secp384r1 -genkey -noout -out jwtES384key.pem
openssl ec -in jwtES384key.pem -pubout -out jwtES384pubkey.pem
```

## ES512

```
openssl ecparam -genkey -name secp521r1 -noout -out ecdsa-p521-private.pem
openssl ec -in ecdsa-p521-private.pem -pubout -out ecdsa-p521-public.pem 
```