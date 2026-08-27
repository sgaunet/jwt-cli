// Package pemkey inspects PEM key material before it reaches a parser.
//
// A password-protected private key is a well-formed PEM block whose payload is
// ciphertext, so x509 reports it as a corrupt ASN.1 structure - "asn1: structure
// error: tags don't match" - which reads like a damaged file and gives no hint
// that the key simply needs decrypting first. Check names the real cause.
package pemkey

import (
	"encoding/pem"
	"errors"
	"fmt"
)

// PEM markers that identify an encrypted private key.
const (
	// blockEncryptedPrivateKey is the PKCS#8 encrypted-key block type.
	blockEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	// headerProcType and headerDEKInfo are the headers OpenSSL's legacy
	// ("traditional") PEM encryption sets. They appear on a block whose type is
	// the ordinary one, e.g. "RSA PRIVATE KEY", which is why the block type
	// alone is not enough to spot them.
	headerProcType = "Proc-Type"
	headerDEKInfo  = "DEK-Info"
	// procTypeEncrypted is the Proc-Type value marking an encrypted block.
	procTypeEncrypted = "4,ENCRYPTED"
)

// ErrEncrypted indicates a password-protected private key, which this tool
// cannot decrypt. Callers wrap it in their own package's key sentinel, so it
// stays matchable from outside internal/.
var ErrEncrypted = errors.New("key file is password-protected")

// decryptCommand names the openssl subcommand that decrypts a block of this
// type while preserving its encoding.
//
// The encoding matters as much as the decryption: "openssl pkey" always writes
// PKCS#8, so pointing it at a SEC 1 EC key would produce a "PRIVATE KEY" block
// that the ECDSA loader does not accept, and the advice would send an operator
// in a circle. "openssl ec" and "openssl rsa" round-trip their own formats.
func decryptCommand(blockType string) string {
	switch blockType {
	case "EC PRIVATE KEY":
		return "openssl ec"
	case "RSA PRIVATE KEY":
		return "openssl rsa"
	default:
		return "openssl pkey"
	}
}

// Check reports ErrEncrypted when keyBytes begins with an encrypted PEM block.
//
// Only the first block is examined: an encrypted key is a single block, and the
// parsers that follow read the first one too.
//
// Input that is not PEM at all returns nil. Raw key bytes are a legitimate form
// for some callers - PASETO accepts them - and there is nothing to inspect.
func Check(keyBytes []byte) error {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil
	}

	fix := fmt.Sprintf("Decrypt it first, e.g. %s -in key.pem -out key.decrypted.pem",
		decryptCommand(block.Type))

	if block.Type == blockEncryptedPrivateKey {
		return fmt.Errorf("%w: PKCS#8 %q block. %s",
			ErrEncrypted, blockEncryptedPrivateKey, fix)
	}

	if block.Headers[headerProcType] == procTypeEncrypted {
		return fmt.Errorf("%w: legacy PEM encryption (%s: %s) on a %q block. %s",
			ErrEncrypted, headerProcType, procTypeEncrypted, block.Type, fix)
	}

	if _, ok := block.Headers[headerDEKInfo]; ok {
		return fmt.Errorf("%w: legacy PEM encryption (%s header) on a %q block. %s",
			ErrEncrypted, headerDEKInfo, block.Type, fix)
	}

	return nil
}
