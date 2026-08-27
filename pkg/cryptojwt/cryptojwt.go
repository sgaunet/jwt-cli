// Package cryptojwt provides JWT encoding and decoding with multiple signing algorithms.
//
// Supported algorithms:
//   - HMAC: HS256, HS384, HS512 (symmetric keys using shared secrets)
//   - RSA: RS256, RS384, RS512 (asymmetric keys using RSA key pairs)
//   - ECDSA: ES256, ES384, ES512 (asymmetric keys using elliptic curve key pairs)
//
// # Security Considerations
//
// Algorithm Validation: All decoders pin the accepted signing algorithm with
// jwt.WithValidMethods, so a token is rejected unless its "alg" header matches
// the exact algorithm the decoder was created for. An HS256 decoder therefore
// rejects an HS384 token even when the shared secret would verify its signature.
// Never use jwt.ParseWithClaims without proper algorithm validation.
//
// Key Strength: HMAC secrets should be at least 256 bits (32 bytes) for HS256.
// Use strong, randomly generated secrets. Enable validation with the
// allowWeakSecret parameter set to false to enforce strong secrets. RSA keys
// must have a modulus of at least 2048 bits; the allowWeakKey parameter lifts
// that floor for testing only.
//
// Claims Validation: Always validate standard JWT claims (exp, nbf, iat) in
// production. The decoder provides parsed claims but does not validate
// time-based claims unless ValidationOptions.ValidateClaims is set, in which
// case exp, nbf and iat are all enforced.
//
// Key Management: For RSA and ECDSA algorithms, protect private keys with
// appropriate file permissions and never commit them to version control.
//
// # Errors
//
// Failures are reported through the sentinel errors ErrInvalidPayload,
// ErrInvalidToken, ErrInvalidKey, ErrWeakSecret, ErrWeakKey and
// ErrUnsupportedAlgorithm. Use errors.Is to test for them. Each error also
// wraps the underlying cause, so errors.Is against os.ErrNotExist or the jwt
// package's own errors keeps working on the same value.
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
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors returned by this package. Use errors.Is to test for them.
var (
	// ErrInvalidPayload indicates the payload is not valid JSON.
	ErrInvalidPayload = errors.New("payload is not a valid JSON")
	// ErrInvalidToken indicates the token is malformed, or its signature could
	// not be verified with the supplied key and pinned algorithm.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidKey indicates the key could not be read or parsed, or is of the
	// wrong type for the chosen algorithm.
	ErrInvalidKey = errors.New("invalid key")
	// ErrWeakSecret indicates an HMAC secret shorter than RFC 7518 requires for
	// the chosen algorithm.
	ErrWeakSecret = errors.New("weak secret")
	// ErrWeakKey indicates an RSA key whose modulus is below the minimum bit
	// length this package accepts.
	ErrWeakKey = errors.New("weak key")
	// ErrUnsupportedAlgorithm indicates a signing method this package does not
	// handle.
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
)

// ValidationOptions configures JWT claims validation behavior.
type ValidationOptions struct {
	// ValidateClaims enables validation of time-based JWT claims (exp, nbf, iat).
	// When false, tokens are accepted regardless of expiration or timing claims.
	// A claim that is absent is never enforced, and iat is rejected only when it
	// lies in the future: a token issued in the past is always accepted.
	ValidateClaims bool
	// ClockSkew allows tolerance for clock differences between systems.
	// Applied to exp, nbf and iat validation. Default is 0 (no tolerance).
	// A negative value tightens the window instead of widening it; the jwt-cli
	// decode commands refuse one.
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
		return "", fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	// A literal "null" unmarshals into a nil map without error, so it needs its
	// own rejection: signing it would produce a token whose payload segment is
	// the four bytes "null" rather than the JSON object RFC 7519 section 4
	// requires, and which decodes back as {}.
	if claims == nil {
		return "", fmt.Errorf("%w: payload must be a JSON object", ErrInvalidPayload)
	}
	// Create token
	token := jwt.NewWithClaims(signingMethod, claims)
	// Generate encoded token and send it as response.
	t, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("%w: failed to sign token: %w", ErrInvalidKey, err)
	}
	return t, nil
}

// DecodeJWT parses and verifies a token, pinning the accepted signing algorithm
// to signingMethod so the untrusted "alg" header cannot select a different one.
func (d *decoder) DecodeJWT(secret any, signingMethod jwt.SigningMethod, token string) (string, error) {
	claims := jwt.MapClaims{}

	// Pin the expected algorithm: the parser rejects any token whose "alg" header
	// differs from the algorithm this decoder was created for.
	validMethods := jwt.WithValidMethods([]string{signingMethod.Alg()})

	// Configure parser based on validation options
	var parser *jwt.Parser
	if d.validationOpts.ValidateClaims {
		// Enable claims validation with optional clock skew.
		//
		// WithIssuedAt turns on the iat rule, which golang-jwt leaves off by
		// default: without it a token dated in the future is accepted even
		// though ValidateClaims covers exp, nbf and iat. WithLeeway applies to
		// iat as well, so ClockSkew still absorbs an issuer whose clock runs
		// ahead.
		parser = jwt.NewParser(
			validMethods,
			jwt.WithLeeway(d.validationOpts.ClockSkew),
			jwt.WithIssuedAt(),
		)
	} else {
		// Disable claims validation for backward compatibility
		parser = jwt.NewParser(
			validMethods,
			jwt.WithoutClaimsValidation(),
		)
	}

	_, err := parser.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
		return secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("%w: failed to parse token: %w", ErrInvalidToken, err)
	}
	res, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	return string(res), nil
}
