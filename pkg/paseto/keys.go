package paseto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/sgaunet/jwt-cli/internal/keyfile"
)

// PEM block types understood by the key loaders.
const (
	pemTypePrivateKey   = "PRIVATE KEY"    // PKCS#8
	pemTypePublicKey    = "PUBLIC KEY"     // PKIX
	pemTypeECPrivateKey = "EC PRIVATE KEY" // SEC 1
)

// Key roles, used to build precise "failed to read ... key file" messages.
const (
	privateKeyRole = "private"
	publicKeyRole  = "public"
)

// readKeyFile reads a key file from disk under the keyfile size bound. role
// names the kind of key being read, so the error identifies which file was at
// fault. An oversized file is additionally reported as ErrInvalidKey, since
// nothing that large can be key material.
func readKeyFile(file, role string) ([]byte, error) {
	keyBytes, err := keyfile.Read(file)
	switch {
	case errors.Is(err, keyfile.ErrTooLarge):
		return nil, fmt.Errorf("%w: failed to read %s key file: %w", ErrInvalidKey, role, err)
	case err != nil:
		return nil, fmt.Errorf("failed to read %s key file: %w", role, err)
	}
	return keyBytes, nil
}

// decodePEM returns the first PEM block in keyBytes, or nil if the input is not
// PEM encoded (in which case it is treated as raw key material).
func decodePEM(keyBytes []byte) *pem.Block {
	block, _ := pem.Decode(keyBytes)
	return block
}

// loadEd25519PrivateKey loads an Ed25519 private key used by PASETO V2 and V4
// public tokens. The file may be a PKCS#8 PEM block or raw key bytes.
func loadEd25519PrivateKey(file string) (ed25519.PrivateKey, error) {
	keyBytes, err := readKeyFile(file, privateKeyRole)
	if err != nil {
		return nil, err
	}

	block := decodePEM(keyBytes)
	if block == nil {
		// Not PEM encoded: treat the file as raw key material.
		if len(keyBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: raw Ed25519 private key must be %d bytes, got %d",
				ErrInvalidKey, ed25519.PrivateKeySize, len(keyBytes))
		}
		return ed25519.PrivateKey(keyBytes), nil
	}

	if block.Type != pemTypePrivateKey {
		return nil, fmt.Errorf("%w: unsupported PEM block type: %s (expected %q)",
			ErrInvalidKey, block.Type, pemTypePrivateKey)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: key is not Ed25519 (got %T)", ErrInvalidKey, parsedKey)
	}
	return privateKey, nil
}

// loadEd25519PublicKey loads an Ed25519 public key used by PASETO V2 and V4
// public tokens. The file may be a PKIX PEM block or raw key bytes.
func loadEd25519PublicKey(file string) (ed25519.PublicKey, error) {
	keyBytes, err := readKeyFile(file, publicKeyRole)
	if err != nil {
		return nil, err
	}

	block := decodePEM(keyBytes)
	if block == nil {
		// Not PEM encoded: treat the file as raw key material.
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: raw Ed25519 public key must be %d bytes, got %d",
				ErrInvalidKey, ed25519.PublicKeySize, len(keyBytes))
		}
		return ed25519.PublicKey(keyBytes), nil
	}

	if block.Type != pemTypePublicKey {
		return nil, fmt.Errorf("%w: unsupported PEM block type: %s (expected %q)",
			ErrInvalidKey, block.Type, pemTypePublicKey)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	publicKey, ok := parsedKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: key is not Ed25519 (got %T)", ErrInvalidKey, parsedKey)
	}
	return publicKey, nil
}

// loadECDSAP384PrivateKey loads a NIST P-384 private key used by PASETO V3
// public tokens.
//
// Both PEM encodings OpenSSL emits are accepted: the SEC 1 "EC PRIVATE KEY"
// block produced by "openssl ecparam -genkey", and the PKCS#8 "PRIVATE KEY"
// block produced by "openssl genpkey".
//
// When the file is not PEM encoded, the parsed key is nil and the raw file
// bytes are returned so the caller can fall back to raw key material.
func loadECDSAP384PrivateKey(file string) (*ecdsa.PrivateKey, []byte, error) {
	keyBytes, err := readKeyFile(file, privateKeyRole)
	if err != nil {
		return nil, nil, err
	}

	block := decodePEM(keyBytes)
	if block == nil {
		return nil, keyBytes, nil
	}

	privateKey, err := parseECDSAPrivateKeyPEM(block)
	if err != nil {
		return nil, nil, err
	}
	if privateKey.Curve != elliptic.P384() {
		return nil, nil, errWrongCurve(privateKey.Curve)
	}
	return privateKey, nil, nil
}

// parseECDSAPrivateKeyPEM parses an ECDSA private key from a SEC 1 or PKCS#8
// PEM block.
func parseECDSAPrivateKeyPEM(block *pem.Block) (*ecdsa.PrivateKey, error) {
	switch block.Type {
	case pemTypeECPrivateKey:
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		return privateKey, nil
	case pemTypePrivateKey:
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key is not ECDSA (got %T)", ErrInvalidKey, parsedKey)
		}
		return privateKey, nil
	default:
		return nil, fmt.Errorf("%w: unsupported PEM block type: %s (expected %q or %q)",
			ErrInvalidKey, block.Type, pemTypeECPrivateKey, pemTypePrivateKey)
	}
}

// loadECDSAP384PublicKey loads a NIST P-384 public key used by PASETO V3 public
// tokens.
//
// When the file is not PEM encoded, the parsed key is nil and the raw file
// bytes are returned so the caller can fall back to raw key material.
func loadECDSAP384PublicKey(file string) (*ecdsa.PublicKey, []byte, error) {
	keyBytes, err := readKeyFile(file, publicKeyRole)
	if err != nil {
		return nil, nil, err
	}

	block := decodePEM(keyBytes)
	if block == nil {
		return nil, keyBytes, nil
	}

	if block.Type != pemTypePublicKey {
		return nil, nil, fmt.Errorf("%w: unsupported PEM block type: %s (expected %q)",
			ErrInvalidKey, block.Type, pemTypePublicKey)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%w: key is not ECDSA (got %T)", ErrInvalidKey, parsedKey)
	}
	if publicKey.Curve != elliptic.P384() {
		return nil, nil, errWrongCurve(publicKey.Curve)
	}
	return publicKey, nil, nil
}

// errWrongCurve reports an ECDSA key on a curve other than the P-384 curve
// PASETO V3 mandates.
func errWrongCurve(curve elliptic.Curve) error {
	return fmt.Errorf("%w: PASETO V3 requires a NIST P-384 key, got %s",
		ErrInvalidKey, curve.Params().Name)
}
