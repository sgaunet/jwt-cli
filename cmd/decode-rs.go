package cmd

import (
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

var decodeRS256Cmd = createAsymmetricDecodeCommand(
	rsKeyVocab,
	"rs256",
	"Decode JWT token using RS256 (RSA-SHA256) algorithm",
	`Decode and verify a JWT token signed with RS256.

RS256 uses RSA signature with SHA-256 hash for verification. You can
provide either the public key (recommended) or the private key for
verification. Using the public key is preferred as it follows the
asymmetric key principle.

Key Requirements:
  - Public or private key in PEM format
  - Key must match the one used for encoding

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key (recommended)
  jwt-cli decode rs256 --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." --public-key RS256.key.pub

  # Decode with private key
  jwt-cli decode rs256 --token "$TOKEN" --private-key RS256.key

  # Decode with claims validation
  jwt-cli decode rs256 --token "$TOKEN" --public-key RS256.key.pub --validate-claims

  # Decode and extract specific field
  jwt-cli decode rs256 --token "$TOKEN" --public-key RS256.key.pub | jq -r '.user'`,
	cryptojwt.NewRS256DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewRS256DecoderWithPrivateKeyFileAndValidation,
)

var decodeRS384Cmd = createAsymmetricDecodeCommand(
	rsKeyVocab,
	"rs384",
	"Decode JWT token using RS384 (RSA-SHA384) algorithm",
	`Decode and verify a JWT token signed with RS384.

RS384 uses RSA signature with SHA-384 hash for verification. You can
provide either the public key (recommended) or the private key.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key
  jwt-cli decode rs384 --token "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9..." --public-key RS384.key.pub

  # Decode with private key
  jwt-cli decode rs384 --token "$TOKEN" --private-key RS384.key

  # Decode with claims validation and clock skew
  jwt-cli decode rs384 --token "$TOKEN" --public-key RS384.key.pub --validate-claims --clock-skew 30s`,
	cryptojwt.NewRS384DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewRS384DecoderWithPrivateKeyFileAndValidation,
)

var decodeRS512Cmd = createAsymmetricDecodeCommand(
	rsKeyVocab,
	"rs512",
	"Decode JWT token using RS512 (RSA-SHA512) algorithm",
	`Decode and verify a JWT token signed with RS512.

RS512 uses RSA signature with SHA-512 hash for verification. You can
provide either the public key (recommended) or the private key.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key
  jwt-cli decode rs512 --token "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9..." --public-key RS512.key.pub

  # Decode with private key
  jwt-cli decode rs512 --token "$TOKEN" --private-key RS512.key

  # Decode with claims validation
  jwt-cli decode rs512 --token "$TOKEN" --public-key RS512.key.pub --validate-claims`,
	cryptojwt.NewRS512DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewRS512DecoderWithPrivateKeyFileAndValidation,
)
