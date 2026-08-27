package cryptojwt

import (
	"fmt"

	"github.com/sgaunet/jwt-cli/internal/pemkey"
)

// checkKeyNotEncrypted rejects password-protected key material.
//
// An encrypted key is a well-formed PEM block whose payload is ciphertext, so
// the x509 parsers report it as a corrupt ASN.1 structure. Catching it here
// names the actual problem instead, and keeps the message consistent with the
// specific ones this package already produces for undersized and wrong-type
// keys.
func checkKeyNotEncrypted(keyBytes []byte) error {
	if err := pemkey.Check(keyBytes); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return nil
}
