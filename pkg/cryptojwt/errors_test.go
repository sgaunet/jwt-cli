package cryptojwt_test

import (
	"crypto/elliptic"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// strongSecret is long enough to satisfy HS512, so secret length never
// interferes with the failure mode a case is meant to exercise.
const strongSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestSentinelErrors checks that each sentinel documented in the package doc is
// reachable with errors.Is from outside the package, for every algorithm family
// that can produce it.
func TestSentinelErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.pem")

	tests := []struct {
		name string
		want error
		call func(t *testing.T) error
	}{
		{
			name: "invalid payload, HS256 encode",
			want: cryptojwt.ErrInvalidPayload,
			call: func(_ *testing.T) error {
				_, err := cryptojwt.NewHS256Encoder([]byte(strongSecret)).Encode("not json")
				return err
			},
		},
		{
			name: "invalid payload, RS256 encode",
			want: cryptojwt.ErrInvalidPayload,
			call: func(t *testing.T) error {
				privateKeyPath, _ := generateRSAKeyPair(t)
				_, err := cryptojwt.NewRS256Encoder(privateKeyPath).Encode("not json")
				return err
			},
		},
		{
			name: "invalid token, HS256 decode",
			want: cryptojwt.ErrInvalidToken,
			call: func(_ *testing.T) error {
				_, err := cryptojwt.NewHS256Encoder([]byte(strongSecret)).Decode("not.a.token")
				return err
			},
		},
		{
			name: "invalid token, ES256 decode",
			want: cryptojwt.ErrInvalidToken,
			call: func(t *testing.T) error {
				privateKeyPath, _ := generateECDSAKeyPair(t, elliptic.P256())
				_, err := cryptojwt.NewES256DecoderWithPrivateKeyFile(privateKeyPath).Decode("not.a.token")
				return err
			},
		},
		{
			name: "weak secret, HS256",
			want: cryptojwt.ErrWeakSecret,
			call: func(_ *testing.T) error {
				_, err := cryptojwt.NewHS256Encoder([]byte("short")).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name: "weak secret, HS512",
			want: cryptojwt.ErrWeakSecret,
			call: func(_ *testing.T) error {
				_, err := cryptojwt.NewHS512Encoder([]byte("short")).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name: "invalid key, RSA private key missing",
			want: cryptojwt.ErrInvalidKey,
			call: func(_ *testing.T) error {
				_, err := cryptojwt.NewRS256Encoder(missing).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name: "invalid key, ECDSA private key missing",
			want: cryptojwt.ErrInvalidKey,
			call: func(_ *testing.T) error {
				_, err := cryptojwt.NewES256Encoder(missing).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name: "invalid key, RSA public key not PEM",
			want: cryptojwt.ErrInvalidKey,
			call: func(t *testing.T) error {
				_, err := cryptojwt.NewRS256DecoderWithPublicKeyFile(createInvalidPEMFile(t)).Decode("not.a.token")
				return err
			},
		},
		{
			name: "invalid key, ECDSA private key not PEM",
			want: cryptojwt.ErrInvalidKey,
			call: func(t *testing.T) error {
				_, err := cryptojwt.NewES256Encoder(createInvalidPEMFile(t)).Encode(`{"a":1}`)
				return err
			},
		},
		{
			name: "invalid key, ECDSA private key of the wrong PEM type",
			want: cryptojwt.ErrInvalidKey,
			call: func(t *testing.T) error {
				_, err := cryptojwt.NewES256Encoder(createWrongTypePEMFile(t, "RSA PRIVATE KEY")).Encode(`{"a":1}`)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(t)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("expected error to match %v, got: %v", tt.want, err)
			}
		})
	}
}

// TestSentinelErrorsPreserveCause checks that wrapping a sentinel keeps the
// underlying cause reachable, so callers can still match on os.ErrNotExist or
// on the jwt package's own errors.
func TestSentinelErrorsPreserveCause(t *testing.T) {
	t.Run("os.ErrNotExist survives the ErrInvalidKey wrap", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.pem")
		_, err := cryptojwt.NewRS256Encoder(missing).Encode(`{"a":1}`)
		if err == nil {
			t.Fatalf("expected an error, got nil")
		}
		if !errors.Is(err, cryptojwt.ErrInvalidKey) {
			t.Errorf("expected error to match ErrInvalidKey, got: %v", err)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected error to still match os.ErrNotExist, got: %v", err)
		}
	})

	t.Run("jwt errors survive the ErrInvalidToken wrap", func(t *testing.T) {
		token, err := cryptojwt.NewHS256Encoder([]byte(strongSecret)).Encode(`{"user":"alice"}`)
		if err != nil {
			t.Fatalf("failed to encode token: %v", err)
		}
		otherSecret := "f" + strongSecret[1:]
		_, err = cryptojwt.NewHS256Encoder([]byte(otherSecret)).Decode(token)
		if err == nil {
			t.Fatalf("expected decoding with the wrong secret to fail")
		}
		if !errors.Is(err, cryptojwt.ErrInvalidToken) {
			t.Errorf("expected error to match ErrInvalidToken, got: %v", err)
		}
		if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			t.Errorf("expected error to still match jwt.ErrTokenSignatureInvalid, got: %v", err)
		}
	})
}
