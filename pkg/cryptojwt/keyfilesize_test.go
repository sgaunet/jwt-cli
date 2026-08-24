package cryptojwt_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
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

// TestOversizedKeyFileIsRejected covers every path that loads key material from
// disk, so an unbounded read cannot creep back into one of them unnoticed.
func TestOversizedKeyFileIsRejected(t *testing.T) {
	path := oversizedKeyFile(t)

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "RS256 encode, private key",
			call: func() error {
				_, err := cryptojwt.NewRS256Encoder(path).Encode(`{"user":"alice"}`)
				return err
			},
		},
		{
			name: "RS256 decode, private key",
			call: func() error {
				_, err := cryptojwt.NewRS256DecoderWithPrivateKeyFile(path).Decode("a.b.c")
				return err
			},
		},
		{
			name: "RS256 decode, public key",
			call: func() error {
				_, err := cryptojwt.NewRS256DecoderWithPublicKeyFile(path).Decode("a.b.c")
				return err
			},
		},
		{
			name: "ES256 encode, private key",
			call: func() error {
				_, err := cryptojwt.NewES256Encoder(path).Encode(`{"user":"alice"}`)
				return err
			},
		},
		{
			name: "ES256 decode, private key",
			call: func() error {
				_, err := cryptojwt.NewES256DecoderWithPrivateKeyFile(path).Decode("a.b.c")
				return err
			},
		},
		{
			name: "ES256 decode, public key",
			call: func() error {
				_, err := cryptojwt.NewES256DecoderWithPublicKeyFile(path).Decode("a.b.c")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("Expected an error for an oversized key file, got nil")
			}
			if !errors.Is(err, cryptojwt.ErrInvalidKey) {
				t.Errorf("Expected errors.Is(err, ErrInvalidKey), got: %v", err)
			}
			if !strings.Contains(err.Error(), "1048576 bytes") {
				t.Errorf("Expected the error to name the size limit, got: %v", err)
			}
		})
	}
}
