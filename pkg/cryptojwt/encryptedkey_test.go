package cryptojwt_test

import (
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// writeEncryptedPEM writes a PEM file that looks encrypted to a parser.
//
// The bytes are not real ciphertext, because they do not need to be: the check
// under test reads the block type and headers, which is precisely why it can run
// before any parser sees the payload.
func writeEncryptedPEM(t *testing.T, blockType string, headers map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "encrypted.pem")
	data := pem.EncodeToMemory(&pem.Block{
		Type:    blockType,
		Headers: headers,
		Bytes:   []byte("ciphertext-stand-in"),
	})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("Failed to write the fixture: %v", err)
	}
	return path
}

// legacyHeaders are what OpenSSL's traditional PEM encryption sets.
func legacyHeaders() map[string]string {
	return map[string]string{
		"Proc-Type": "4,ENCRYPTED",
		"DEK-Info":  "AES-256-CBC,0123456789ABCDEF0123456789ABCDEF",
	}
}

// TestEncryptedKeyIsNamedAsSuch covers every key-loading path.
//
// A password-protected key used to surface as "asn1: structure error: tags don't
// match (2 vs {class:0 tag:16 ...})", which reads like a corrupt file and sends
// an operator looking for the wrong problem. The tool already produced accurate
// messages for undersized and wrong-type keys, so this was an inconsistency.
func TestEncryptedKeyIsNamedAsSuch(t *testing.T) {
	validating := cryptojwt.ValidationOptions{}

	tests := []struct {
		name      string
		blockType string
		headers   map[string]string
		call      func(t *testing.T, keyPath string) error
	}{
		{
			name:      "RSA encode, PKCS#8 encrypted",
			blockType: "ENCRYPTED PRIVATE KEY",
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewRS256EncoderWithOptions(keyPath, false).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name:      "RSA encode, legacy headers",
			blockType: "RSA PRIVATE KEY",
			headers:   legacyHeaders(),
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewRS256EncoderWithOptions(keyPath, false).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name:      "RSA decode with a private key",
			blockType: "ENCRYPTED PRIVATE KEY",
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewRS256DecoderWithPrivateKeyFileAndValidation(
					keyPath, validating).Decode("irrelevant")
				return err
			},
		},
		{
			name:      "RSA decode with a public key",
			blockType: "ENCRYPTED PRIVATE KEY",
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewRS256DecoderWithPublicKeyFileAndValidation(
					keyPath, validating).Decode("irrelevant")
				return err
			},
		},
		{
			name:      "ECDSA encode, PKCS#8 encrypted",
			blockType: "ENCRYPTED PRIVATE KEY",
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewES256Encoder(keyPath).Encode(`{"a":1}`)
				return err
			},
		},
		{
			// The case the check ordering exists for: this block keeps the
			// ordinary EC type, so it passes the block-type check and would
			// otherwise die inside x509 with a raw ASN.1 error.
			name:      "ECDSA encode, legacy headers on an EC PRIVATE KEY block",
			blockType: "EC PRIVATE KEY",
			headers:   legacyHeaders(),
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewES256Encoder(keyPath).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name:      "ECDSA decode with a private key",
			blockType: "EC PRIVATE KEY",
			headers:   legacyHeaders(),
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation(
					keyPath, validating).Decode("irrelevant")
				return err
			},
		},
		{
			name:      "ECDSA decode with a public key",
			blockType: "ENCRYPTED PRIVATE KEY",
			call: func(_ *testing.T, keyPath string) error {
				_, err := cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation(
					keyPath, validating).Decode("irrelevant")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := writeEncryptedPEM(t, tt.blockType, tt.headers)

			err := tt.call(t, keyPath)
			if err == nil {
				t.Fatal("Expected an encrypted key to be rejected, got no error")
			}
			if !errors.Is(err, cryptojwt.ErrInvalidKey) {
				t.Errorf("Expected ErrInvalidKey, got: %v", err)
			}
			if !strings.Contains(err.Error(), "password-protected") {
				t.Errorf("Expected the error to name the real cause, got: %v", err)
			}
			if strings.Contains(err.Error(), "asn1") {
				t.Errorf("Expected no raw ASN.1 noise in the error, got: %v", err)
			}
		})
	}
}

// TestPlainKeysStillLoad keeps the check from becoming a false positive: an
// ordinary key must be unaffected.
func TestPlainKeysStillLoad(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		privateKey, publicKey := generateRSAKeyPair(t)
		token, err := cryptojwt.NewRS256EncoderWithOptions(privateKey, false).Encode(`{"a":1}`)
		if err != nil {
			t.Fatalf("Expected a plain RSA key to load, got: %v", err)
		}
		if _, err := cryptojwt.NewRS256DecoderWithPublicKeyFileAndValidation(
			publicKey, cryptojwt.ValidationOptions{}).Decode(token); err != nil {
			t.Errorf("Expected a plain RSA public key to load, got: %v", err)
		}
	})
}
