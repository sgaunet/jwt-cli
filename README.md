# jwt-cli

jwt-cli is a utility to encode/decode JWT token.

```
Tool to encode/decode JWT token

Usage:
  jwt-cli [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  decode      decode JWT token
  encode      encode JWT token
  help        Help about any command
  methods     print list of signing methods
  version     print version of jwt-cli

Flags:
  -h, --help       help for jwt-cli
      --m string   Signing Method 
      --s string   JWT secret

Use "jwt-cli [command] --help" for more information about a command.
```

Supported methods are actually:

* HS256
* HS384
* HS512


# Install

## Option 1

* Download the release
* Install the binary in /usr/local/bin 

## Option 2: With brew

```
brew tap sgaunet/tools
brew install jwt-cli
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

