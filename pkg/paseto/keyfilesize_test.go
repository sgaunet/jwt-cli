package paseto_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

// oversizedKeyFile creates a key file one byte past the 1 MiB bound. It
// truncates rather than writing, so the fixture is sparse and instant.
func oversizedKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oversized.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("Failed to create fixture: %v", err)
	}
	if err := os.Truncate(path, (1<<20)+1); err != nil {
		t.Fatalf("Failed to size fixture: %v", err)
	}
	return path
}

// TestOversizedKeyFileIsRejected covers the Ed25519 (V2/V4) and P-384 (V3)
// loaders, which all funnel through readKeyFile.
func TestOversizedKeyFileIsRejected(t *testing.T) {
	path := oversizedKeyFile(t)

	tests := []struct {
		name string
		call func() error
	}{
		{"V4 private key", func() error { _, err := paseto.NewPublicV4EncoderFromPrivateKey(path); return err }},
		{"V4 public key", func() error { _, err := paseto.NewPublicV4DecoderFromPublicKey(path); return err }},
		{"V3 private key", func() error { _, err := paseto.NewPublicV3EncoderFromPrivateKey(path); return err }},
		{"V3 public key", func() error { _, err := paseto.NewPublicV3DecoderFromPublicKey(path); return err }},
		{"V2 private key", func() error { _, err := paseto.NewPublicV2EncoderFromPrivateKey(path); return err }},
		{"V2 public key", func() error { _, err := paseto.NewPublicV2DecoderFromPublicKey(path); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("Expected an error for an oversized key file, got nil")
			}
			if !errors.Is(err, paseto.ErrInvalidKey) {
				t.Errorf("Expected errors.Is(err, ErrInvalidKey), got: %v", err)
			}
			if !strings.Contains(err.Error(), "1048576 bytes") {
				t.Errorf("Expected the error to name the size limit, got: %v", err)
			}
			// The role prefix the existing loaders promise must survive.
			if !strings.Contains(err.Error(), "key file") {
				t.Errorf("Expected the error to identify the key file, got: %v", err)
			}
		})
	}
}
