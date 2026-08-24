package cmd

import (
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

var decodeES256Cmd = createAsymmetricDecodeCommand(
	esKeyVocab,
	"es256",
	"Decode JWT token using ES256 (ECDSA-SHA256) algorithm",
	`Decode and verify a JWT token signed with ES256.

ES256 uses ECDSA with SHA-256 hash and P-256 curve for verification.
You can provide either the public key (recommended) or the private key.

Key Requirements:
  - Public or private key in PEM format using P-256 curve
  - Key must match the one used for encoding

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key (recommended)
  jwt-cli decode es256 --token "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..." --public-key ecdsa-p256-public.pem

  # Decode with private key
  jwt-cli decode es256 --token "$TOKEN" --private-key ecdsa-p256-private.pem

  # Decode with claims validation
  jwt-cli decode es256 --token "$TOKEN" --public-key ecdsa-p256-public.pem --validate-claims

  # Decode and extract specific field
  jwt-cli decode es256 --token "$TOKEN" --public-key ecdsa-p256-public.pem | jq -r '.user'`,
	cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation,
)

var decodeES384Cmd = createAsymmetricDecodeCommand(
	esKeyVocab,
	"es384",
	"Decode JWT token using ES384 (ECDSA-SHA384) algorithm",
	`Decode and verify a JWT token signed with ES384.

ES384 uses ECDSA with SHA-384 hash and P-384 curve for verification.
You can provide either the public key (recommended) or the private key.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key
  jwt-cli decode es384 --token "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9..." --public-key jwtES384pubkey.pem

  # Decode with private key
  jwt-cli decode es384 --token "$TOKEN" --private-key jwtES384key.pem

  # Decode with claims validation
  jwt-cli decode es384 --token "$TOKEN" --public-key jwtES384pubkey.pem --validate-claims`,
	cryptojwt.NewES384DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewES384DecoderWithPrivateKeyFileAndValidation,
)

var decodeES512Cmd = createAsymmetricDecodeCommand(
	esKeyVocab,
	"es512",
	"Decode JWT token using ES512 (ECDSA-SHA512) algorithm",
	`Decode and verify a JWT token signed with ES512.

ES512 uses ECDSA with SHA-512 hash and P-521 curve for verification.
You can provide either the public key (recommended) or the private key.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key
  jwt-cli decode es512 --token "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9..." --public-key ecdsa-p521-public.pem

  # Decode with private key
  jwt-cli decode es512 --token "$TOKEN" --private-key ecdsa-p521-private.pem

  # Decode with claims validation and clock skew
  jwt-cli decode es512 --token "$TOKEN" --public-key ecdsa-p521-public.pem --validate-claims --clock-skew 2m`,
	cryptojwt.NewES512DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewES512DecoderWithPrivateKeyFileAndValidation,
)
