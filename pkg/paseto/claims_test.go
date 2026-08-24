package paseto_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

// newLocalKey returns a fresh hex-encoded 32-byte symmetric key.
func newLocalKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	return hex.EncodeToString(key)
}

func TestRegisteredClaims(t *testing.T) {
	keyHex := newLocalKey(t)

	encoder, err := paseto.NewLocalV4Encoder(keyHex)
	if err != nil {
		t.Fatalf("Failed to create encoder: %v", err)
	}

	// Both accepted forms must produce the same RFC 3339 claim, since PASETO
	// stores registered time claims as RFC 3339 strings.
	t.Run("time claims accept RFC 3339 and Unix timestamps", func(t *testing.T) {
		for _, tt := range []struct {
			name    string
			payload string
		}{
			{"RFC 3339 string", `{"exp": "2025-01-01T00:00:00Z"}`},
			{"Unix timestamp", `{"exp": 1735689600}`},
		} {
			t.Run(tt.name, func(t *testing.T) {
				token, err := encoder.Encode(tt.payload)
				if err != nil {
					t.Fatalf("Failed to encode: %v", err)
				}
				decoded, err := encoder.Decode(token)
				if err != nil {
					t.Fatalf("Failed to decode: %v", err)
				}
				if !strings.Contains(decoded, "2025-01-01T00:00:00Z") {
					t.Errorf("Expected exp to round-trip as RFC 3339, got: %s", decoded)
				}
			})
		}
	})

	t.Run("nbf and iat accept Unix timestamps", func(t *testing.T) {
		token, err := encoder.Encode(`{"nbf": 1735689600, "iat": 1735689600}`)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		for _, claim := range []string{"nbf", "iat"} {
			if !strings.Contains(decoded, claim) {
				t.Errorf("Expected decoded payload to contain %q, got: %s", claim, decoded)
			}
		}
	})

	// Regression: these previously produced a token with the claim silently
	// missing, so a caller believed the token was time-bound when it was not.
	t.Run("unparsable time claims are rejected", func(t *testing.T) {
		for _, payload := range []string{
			`{"exp": "not-a-date"}`,
			`{"nbf": "not-a-date"}`,
			`{"iat": true}`,
			`{"exp": {"nested": "object"}}`,
		} {
			_, err := encoder.Encode(payload)
			if err == nil {
				t.Fatalf("Expected error for payload %s", payload)
			}
			if !errors.Is(err, paseto.ErrInvalidClaim) {
				t.Errorf("Expected ErrInvalidClaim for %s, got: %v", payload, err)
			}
		}
	})

	t.Run("non-string registered claims are rejected", func(t *testing.T) {
		for _, payload := range []string{
			`{"iss": 123}`,
			`{"sub": false}`,
			`{"aud": ["a", "b"]}`,
			`{"jti": 1}`,
		} {
			_, err := encoder.Encode(payload)
			if err == nil {
				t.Fatalf("Expected error for payload %s", payload)
			}
			if !errors.Is(err, paseto.ErrInvalidClaim) {
				t.Errorf("Expected ErrInvalidClaim for %s, got: %v", payload, err)
			}
		}
	})

	t.Run("string registered claims round-trip", func(t *testing.T) {
		token, err := encoder.Encode(
			`{"iss": "issuer", "sub": "subject", "aud": "audience", "jti": "id-1"}`)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		for _, want := range []string{"issuer", "subject", "audience", "id-1"} {
			if !strings.Contains(decoded, want) {
				t.Errorf("Expected decoded payload to contain %q, got: %s", want, decoded)
			}
		}
	})

	t.Run("custom claims are preserved", func(t *testing.T) {
		token, err := encoder.Encode(`{"role": "admin", "count": 3}`)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "admin") {
			t.Errorf("Expected decoded payload to contain 'admin', got: %s", decoded)
		}
	})

	// Decoding deliberately performs no claims validation, so an already
	// expired token still decodes. This documents that contract.
	t.Run("expired tokens still decode", func(t *testing.T) {
		token, err := encoder.Encode(`{"exp": "2000-01-01T00:00:00Z"}`)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if _, err := encoder.Decode(token); err != nil {
			t.Fatalf("Expected expired token to decode, got: %v", err)
		}
	})
}

// TestCrossVersionRejection verifies that a token minted by one PASETO version
// cannot be decoded by another, so version confusion is not possible.
func TestCrossVersionRejection(t *testing.T) {
	keyHex := newLocalKey(t)

	v4, err := paseto.NewLocalV4Encoder(keyHex)
	if err != nil {
		t.Fatalf("Failed to create V4 encoder: %v", err)
	}
	v3, err := paseto.NewLocalV3Encoder(keyHex)
	if err != nil {
		t.Fatalf("Failed to create V3 encoder: %v", err)
	}
	v2, err := paseto.NewLocalV2Encoder(keyHex)
	if err != nil {
		t.Fatalf("Failed to create V2 encoder: %v", err)
	}

	encoders := map[string]paseto.EncoderDecoder{"v4": v4, "v3": v3, "v2": v2}

	for mintedBy, encoder := range encoders {
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with %s: %v", mintedBy, err)
		}
		for decodedBy, decoder := range encoders {
			if decodedBy == mintedBy {
				continue
			}
			t.Run(mintedBy+" token rejected by "+decodedBy+" decoder", func(t *testing.T) {
				if _, err := decoder.Decode(token); err == nil {
					t.Fatalf("Expected %s decoder to reject a %s token", decodedBy, mintedBy)
				}
			})
		}
	}
}

// TestLocalErrorPaths gives the V3 and V2 local codecs the same error coverage
// the V4 codec already had.
func TestLocalErrorPaths(t *testing.T) {
	for _, tt := range []struct {
		name string
		ctor func(string) (paseto.EncoderDecoder, error)
	}{
		{"v3", func(k string) (paseto.EncoderDecoder, error) { return paseto.NewLocalV3Encoder(k) }},
		{"v2", func(k string) (paseto.EncoderDecoder, error) { return paseto.NewLocalV2Encoder(k) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keyHex := newLocalKey(t)
			encoder, err := tt.ctor(keyHex)
			if err != nil {
				t.Fatalf("Failed to create encoder: %v", err)
			}

			t.Run("encode with invalid JSON", func(t *testing.T) {
				if _, err := encoder.Encode(invalidJSON); err == nil {
					t.Fatal("Expected error for invalid JSON")
				} else if !errors.Is(err, paseto.ErrInvalidPayload) {
					t.Errorf("Expected ErrInvalidPayload, got: %v", err)
				}
			})

			t.Run("decode with invalid token", func(t *testing.T) {
				if _, err := encoder.Decode("invalid.token.here"); err == nil {
					t.Fatal("Expected error for invalid token")
				} else if !errors.Is(err, paseto.ErrInvalidToken) {
					t.Errorf("Expected ErrInvalidToken, got: %v", err)
				}
			})

			t.Run("decode with wrong key", func(t *testing.T) {
				token, err := encoder.Encode(validPayload)
				if err != nil {
					t.Fatalf("Failed to encode: %v", err)
				}
				other, err := tt.ctor(newLocalKey(t))
				if err != nil {
					t.Fatalf("Failed to create second encoder: %v", err)
				}
				if _, err := other.Decode(token); err == nil {
					t.Fatal("Expected error when decoding with the wrong key")
				}
			})

			t.Run("invalid key hex", func(t *testing.T) {
				if _, err := tt.ctor("invalid-hex"); err == nil {
					t.Fatal("Expected error for invalid hex")
				} else if !errors.Is(err, paseto.ErrInvalidKey) {
					t.Errorf("Expected ErrInvalidKey, got: %v", err)
				}
			})

			t.Run("wrong key size", func(t *testing.T) {
				short := make([]byte, 16)
				if _, err := rand.Read(short); err != nil {
					t.Fatalf("Failed to generate key: %v", err)
				}
				if _, err := tt.ctor(hex.EncodeToString(short)); err == nil {
					t.Fatal("Expected error for wrong key size")
				} else if !errors.Is(err, paseto.ErrInvalidKey) {
					t.Errorf("Expected ErrInvalidKey, got: %v", err)
				}
			})
		})
	}
}
