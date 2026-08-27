package cryptojwt_test

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// iatTestSecret is long enough for HS256's RFC 7518 minimum.
const iatTestSecret = "test-secret-key-for-hs256-32bytes"

// TestIssuedAtValidation covers the iat rule that ValidationOptions has always
// advertised and never applied.
//
// golang-jwt leaves its iat check off unless WithIssuedAt is passed, so a token
// stamped in the future used to decode cleanly under ValidateClaims even though
// the flag help and this package's docs both list iat alongside exp and nbf.
func TestIssuedAtValidation(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name        string
		payload     string
		validate    bool
		clockSkew   time.Duration
		expectError bool
	}{
		{
			name:        "iat one hour in the future is rejected",
			payload:     fmt.Sprintf(`{"user":"test","iat":%d}`, now+3600),
			validate:    true,
			expectError: true,
		},
		{
			name:        "iat in the future within the clock skew is accepted",
			payload:     fmt.Sprintf(`{"user":"test","iat":%d}`, now+30),
			validate:    true,
			clockSkew:   5 * time.Minute,
			expectError: false,
		},
		{
			name:        "iat in the future beyond the clock skew is rejected",
			payload:     fmt.Sprintf(`{"user":"test","iat":%d}`, now+600),
			validate:    true,
			clockSkew:   1 * time.Minute,
			expectError: true,
		},
		{
			name:        "iat in the past is accepted",
			payload:     fmt.Sprintf(`{"user":"test","iat":%d}`, now-3600),
			validate:    true,
			expectError: false,
		},
		{
			name:        "absent iat is accepted",
			payload:     `{"user":"test"}`,
			validate:    true,
			expectError: false,
		},
		{
			// golang-jwt reads a numeric date of exactly 0 as "claim absent",
			// so this grants nothing that omitting iat would not.
			name:        "iat of zero is treated as absent",
			payload:     `{"user":"test","iat":0}`,
			validate:    true,
			expectError: false,
		},
		{
			// The default stays permissive so a token can always be inspected.
			name:        "future iat is accepted when validation is off",
			payload:     fmt.Sprintf(`{"user":"test","iat":%d}`, now+3600),
			validate:    false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := cryptojwt.NewHS256EncoderWithOptions([]byte(iatTestSecret), false)
			token, err := encoder.Encode(tt.payload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			decoder := cryptojwt.NewHS256DecoderWithValidation(
				[]byte(iatTestSecret), false, cryptojwt.ValidationOptions{
					ValidateClaims: tt.validate,
					ClockSkew:      tt.clockSkew,
				})

			claims, err := decoder.Decode(token)
			switch {
			case tt.expectError && err == nil:
				t.Fatalf("Expected the token to be rejected, got claims: %s", claims)
			case !tt.expectError && err != nil:
				t.Fatalf("Expected the token to be accepted, got: %v", err)
			}

			if tt.expectError {
				if !errors.Is(err, cryptojwt.ErrInvalidToken) {
					t.Errorf("Expected ErrInvalidToken, got: %v", err)
				}
				if !errors.Is(err, jwt.ErrTokenUsedBeforeIssued) {
					t.Errorf("Expected ErrTokenUsedBeforeIssued to be wrapped, got: %v", err)
				}
			}
		})
	}
}

// TestIssuedAtValidationAcrossAlgorithms confirms the rule reaches every
// algorithm family, since all of them share the same decoder core.
func TestIssuedAtValidationAcrossAlgorithms(t *testing.T) {
	futureIat := fmt.Sprintf(`{"user":"test","iat":%d}`, time.Now().Add(time.Hour).Unix())
	validating := cryptojwt.ValidationOptions{ValidateClaims: true}

	t.Run("HS384", func(t *testing.T) {
		secret := []byte("test-secret-key-for-hs384-48-bytes-long-padding!")
		token, err := cryptojwt.NewHS384EncoderWithOptions(secret, false).Encode(futureIat)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if _, err := cryptojwt.NewHS384DecoderWithValidation(secret, false, validating).
			Decode(token); err == nil {
			t.Error("Expected HS384 to reject a future-dated iat")
		}
	})

	t.Run("RS256", func(t *testing.T) {
		privateKey, publicKey := generateRSAKeyPair(t)
		token, err := cryptojwt.NewRS256EncoderWithOptions(privateKey, false).Encode(futureIat)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		decoder := cryptojwt.NewRS256DecoderWithPublicKeyFileAndValidation(publicKey, validating)
		if _, err := decoder.Decode(token); err == nil {
			t.Error("Expected RS256 to reject a future-dated iat")
		}
	})

	t.Run("ES256", func(t *testing.T) {
		privateKey, publicKey := generateECDSAKeyPair(t, elliptic.P256())
		token, err := cryptojwt.NewES256Encoder(privateKey).Encode(futureIat)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		decoder := cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation(publicKey, validating)
		if _, err := decoder.Decode(token); err == nil {
			t.Error("Expected ES256 to reject a future-dated iat")
		}
	})
}
