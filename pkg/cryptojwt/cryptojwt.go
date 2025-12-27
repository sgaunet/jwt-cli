// Package cryptojwt provides JWT encoding and decoding with multiple signing algorithms.
//
// Supported algorithms:
//   - HMAC: HS256, HS384, HS512 (symmetric keys using shared secrets)
//   - RSA: RS256, RS384, RS512 (asymmetric keys using RSA key pairs)
//   - ECDSA: ES256, ES384, ES512 (asymmetric keys using elliptic curve key pairs)
//
// # Security Considerations
//
// Algorithm Validation: All decoders validate that the token's algorithm
// matches the expected algorithm to prevent algorithm confusion attacks.
// Never use jwt.ParseWithClaims without proper algorithm validation.
//
// Key Strength: HMAC secrets should be at least 256 bits (32 bytes) for HS256.
// Use strong, randomly generated secrets. Enable validation with the
// allowWeakSecret parameter set to false to enforce strong secrets.
//
// Claims Validation: Always validate standard JWT claims (exp, nbf, iat) in
// production. The decoder provides parsed claims but does not automatically
// validate expiration or time-based claims.
//
// Key Management: For RSA and ECDSA algorithms, protect private keys with
// appropriate file permissions and never commit them to version control.
//
// # Usage Examples
//
// HMAC (HS256) encoding and decoding:
//
//	encoder := cryptojwt.NewHSJWT(256, "my-secret-key", "")
//	token, err := encoder.Encode(`{"user":"alice","role":"admin"}`)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	decoder := cryptojwt.NewHSJWT(256, "my-secret-key", "")
//	claims, err := decoder.Decode(token)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(claims)
//
// RSA (RS256) encoding with private key and decoding with public key:
//
//	encoder := cryptojwt.NewRSJWT(256, "private.pem", "")
//	token, err := encoder.Encode(`{"user":"bob"}`)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	decoder := cryptojwt.NewRSJWT(256, "", "public.pem")
//	claims, err := decoder.Decode(token)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// ECDSA (ES256) similar to RSA but uses elliptic curve keys:
//
//	encoder := cryptojwt.NewESJWT(256, "ec-private.pem", "")
//	token, err := encoder.Encode(`{"user":"charlie"}`)
package cryptojwt

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ValidationOptions configures JWT claims validation behavior.
type ValidationOptions struct {
	// ValidateClaims enables validation of time-based JWT claims (exp, nbf, iat).
	// When false, tokens are accepted regardless of expiration or timing claims.
	ValidateClaims bool
	// ClockSkew allows tolerance for clock differences between systems.
	// Applied to exp and nbf validation. Default is 0 (no tolerance).
	ClockSkew time.Duration
}

// Encoder is the interface for encoding JWT tokens.
type Encoder interface {
	Encode(payload string) (string, error)
}

// Decoder is the interface for decoding JWT tokens.
type Decoder interface {
	Decode(token string) (string, error)
}

// EncoderDecoder is the interface for encoding and decoding JWT tokens.
type EncoderDecoder interface {
	Encoder
	Decoder
}

type encoder struct {
}

type decoder struct {
	validationOpts ValidationOptions
}

func (e *encoder) EncodeJWT(secret any, signingMethod jwt.SigningMethod, payload string) (string, error) {
	claims := jwt.MapClaims{}
	err := json.Unmarshal([]byte(payload), &claims)
	if err != nil {
		return "", fmt.Errorf("payload is not a valid JSON: %w", err)
	}
	// Create token
	token := jwt.NewWithClaims(signingMethod, claims)
	// Generate encoded token and send it as response.
	t, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return t, nil
}

func (d *decoder) DecodeJWT(secret any, token string) (string, error) {
	claims := jwt.MapClaims{}

	// Configure parser based on validation options
	var parser *jwt.Parser
	if d.validationOpts.ValidateClaims {
		// Enable claims validation with optional clock skew
		parser = jwt.NewParser(
			jwt.WithLeeway(d.validationOpts.ClockSkew),
		)
	} else {
		// Disable claims validation for backward compatibility
		parser = jwt.NewParser(
			jwt.WithoutClaimsValidation(),
		)
	}

	_, err := parser.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
		return secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}
	res, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	return string(res), nil
}
