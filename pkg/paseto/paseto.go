// Package paseto provides encoding and decoding of PASETO (Platform-Agnostic
// SEcurity TOkens) in all three supported versions: V2, V3 and V4.
//
// Two token purposes are supported:
//
//   - local: symmetric encryption using a hex-encoded key.
//   - public: asymmetric signing using Ed25519 keys (V2/V4) or NIST P-384
//     keys (V3). Key files may be supplied as PEM or as raw key bytes.
//
// # Claims
//
// Payloads are supplied as JSON. The PASETO registered claims exp, nbf and iat
// accept either an RFC 3339 string or a numeric Unix timestamp; both are stored
// in the RFC 3339 form the PASETO specification requires. A value that cannot be
// interpreted returns ErrInvalidClaim rather than being silently discarded.
//
// # Security considerations
//
// Decoding verifies the token's signature or authentication tag. By default it
// performs no claims validation: expired (exp), not-yet-valid (nbf) and
// audience claims are NOT enforced, which mirrors the inspection-oriented
// behaviour of the jwt-cli command line tool.
//
// Pass WithValidation to a constructor to opt into validation of the
// time-based claims exp and nbf, with an optional clock-skew tolerance; a
// token failing either rule reports ErrClaimsNotValid. A claim that is absent
// is not enforced, matching the JWT decode path. The aud and iat claims are
// never enforced: callers needing those guarantees must inspect the returned
// claims themselves.
package paseto

import (
	"errors"
	"fmt"

	"aidanwoods.dev/go-paseto"
)

// EncoderDecoder encodes a JSON payload into a PASETO token and decodes a
// PASETO token back into its JSON claims.
type EncoderDecoder interface {
	// Encode serialises the JSON payload into a PASETO token.
	Encode(payload string) (string, error)
	// Decode verifies the token and returns its claims as indented JSON,
	// discarding any footer.
	Decode(token string) (string, error)
	// DecodeWithFooter verifies the token and returns its claims together with
	// its footer, which PASETO authenticates but keeps outside the claim set.
	DecodeWithFooter(token string) (DecodedToken, error)
}

// Sentinel errors returned by this package. Use errors.Is to test for them.
var (
	// ErrInvalidPayload indicates the payload is not valid JSON.
	ErrInvalidPayload = errors.New("payload is not a valid JSON")
	// ErrInvalidToken indicates the token is malformed, or its signature or
	// authentication tag could not be verified with the supplied key.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidKey indicates the key could not be parsed, is of the wrong
	// type or curve, or has the wrong length for the chosen PASETO version.
	ErrInvalidKey = errors.New("invalid key")
	// ErrInvalidClaim indicates a registered claim held a value of an
	// unusable type or format, such as a non-parsable exp.
	ErrInvalidClaim = errors.New("invalid claim")
	// ErrClaimsNotValid indicates a token that verified cryptographically but
	// was rejected by claims validation, which WithValidation enables. Where a
	// specific rule failed it wraps ErrTokenExpired or ErrTokenNotYetValid.
	ErrClaimsNotValid = errors.New("claims validation failed")
	// ErrTokenExpired indicates a token whose exp claim has already passed.
	ErrTokenExpired = errors.New("token has expired")
	// ErrTokenNotYetValid indicates a token whose nbf claim has not been reached.
	ErrTokenNotYetValid = errors.New("token is not valid yet")
)

// wrapDecodeError classifies a parse failure. A rule failure means the token
// verified cryptographically but its claims were rejected; anything else means
// the token itself did not verify.
func wrapDecodeError(err error) error {
	if errors.Is(err, paseto.RuleError{}) {
		return fmt.Errorf("%w: %w", ErrClaimsNotValid, err)
	}
	return fmt.Errorf("%w: %w", ErrInvalidToken, err)
}
