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
// Decoding verifies the token's signature or authentication tag, but performs
// no claims validation: expired (exp), not-yet-valid (nbf) and audience claims
// are NOT enforced. Callers that need those guarantees must inspect the
// returned claims themselves. This mirrors the inspection-oriented behaviour of
// the jwt-cli command line tool.
package paseto

import (
	"encoding/json"
	"errors"
	"fmt"
)

// EncoderDecoder encodes a JSON payload into a PASETO token and decodes a
// PASETO token back into its JSON claims.
type EncoderDecoder interface {
	// Encode serialises the JSON payload into a PASETO token.
	Encode(payload string) (string, error)
	// Decode verifies the token and returns its claims as indented JSON.
	Decode(token string) (string, error)
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
)

// validateJSONPayload reports whether payload is syntactically valid JSON.
func validateJSONPayload(payload string) error {
	var js json.RawMessage
	if err := json.Unmarshal([]byte(payload), &js); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	return nil
}
