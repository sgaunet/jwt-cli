package paseto_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	gopaseto "aidanwoods.dev/go-paseto"
	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

// validationCase is one PASETO version and purpose, with a factory that builds
// a codec able to both encode and decode, applying the given options.
type validationCase struct {
	name     string
	newCodec func(t *testing.T, opts ...paseto.Option) paseto.EncoderDecoder
}

// localKeyHex returns a fresh hex-encoded 32-byte symmetric key.
func localKeyHex(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	return hex.EncodeToString(key)
}

// validationCases covers every version and purpose. Key material is generated
// once per call so a case can encode and decode with two separate codecs.
func validationCases(t *testing.T) []validationCase {
	t.Helper()
	keyHex := localKeyHex(t)
	edPrivate, _ := ed25519PEMKeyPair(t)
	p384Private, _ := p384PEMKeyPair(t, p384Key(t), true)

	build := func(name string, fn func(opts ...paseto.Option) (paseto.EncoderDecoder, error)) validationCase {
		return validationCase{
			name: name,
			newCodec: func(t *testing.T, opts ...paseto.Option) paseto.EncoderDecoder {
				t.Helper()
				codec, err := fn(opts...)
				if err != nil {
					t.Fatalf("Failed to create %s codec: %v", name, err)
				}
				return codec
			},
		}
	}

	return []validationCase{
		build("v4.local", func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
			return paseto.NewLocalV4Encoder(keyHex, opts...)
		}),
		build("v3.local", func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
			return paseto.NewLocalV3Encoder(keyHex, opts...)
		}),
		build("v2.local", func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
			return paseto.NewLocalV2Encoder(keyHex, opts...)
		}),
		build("v4.public", func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
			return paseto.NewPublicV4EncoderFromPrivateKey(edPrivate, opts...)
		}),
		build("v3.public", func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
			return paseto.NewPublicV3EncoderFromPrivateKey(p384Private, opts...)
		}),
		build("v2.public", func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
			return paseto.NewPublicV2EncoderFromPrivateKey(edPrivate, opts...)
		}),
	}
}

// validating is the option every opt-in case uses, with no clock skew.
func validating() paseto.Option {
	return paseto.WithValidation(paseto.ValidationOptions{ValidateClaims: true})
}

// payloadWithExp renders a payload whose exp claim is offset from now.
func payloadWithExp(offset time.Duration) string {
	return fmt.Sprintf(`{"email":"user@example.com","exp":%d}`, time.Now().Add(offset).Unix())
}

// payloadWithNbf renders a payload whose nbf claim is offset from now.
func payloadWithNbf(offset time.Duration) string {
	return fmt.Sprintf(`{"email":"user@example.com","nbf":%d}`, time.Now().Add(offset).Unix())
}

// encodeWith encodes payload with a codec built without validation, so the
// resulting token is always cryptographically sound whatever its claims say.
func encodeWith(t *testing.T, c validationCase, payload string) string {
	t.Helper()
	token, err := c.newCodec(t).Encode(payload)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}
	return token
}

// TestDecodeWithoutValidationIgnoresTimeClaims pins the package default: an
// expired or not-yet-valid token still decodes, so its contents can be read.
func TestDecodeWithoutValidationIgnoresTimeClaims(t *testing.T) {
	for _, c := range validationCases(t) {
		t.Run(c.name, func(t *testing.T) {
			for name, payload := range map[string]string{
				"expired":       payloadWithExp(-time.Hour),
				"not yet valid": payloadWithNbf(time.Hour),
			} {
				token := encodeWith(t, c, payload)
				decoded, err := c.newCodec(t).Decode(token)
				if err != nil {
					t.Fatalf("Expected %s token to decode by default, got: %v", name, err)
				}
				if !strings.Contains(decoded, "user@example.com") {
					t.Errorf("Expected claims in output, got: %s", decoded)
				}
			}
		})
	}
}

// TestDecodeWithValidationRejectsExpiredToken covers the opt-in exp rule.
func TestDecodeWithValidationRejectsExpiredToken(t *testing.T) {
	for _, c := range validationCases(t) {
		t.Run(c.name, func(t *testing.T) {
			token := encodeWith(t, c, payloadWithExp(-time.Hour))

			_, err := c.newCodec(t, validating()).Decode(token)
			if err == nil {
				t.Fatal("Expected an error for an expired token")
			}
			if !errors.Is(err, paseto.ErrClaimsNotValid) {
				t.Errorf("Expected ErrClaimsNotValid, got: %v", err)
			}
			if !errors.Is(err, paseto.ErrTokenExpired) {
				t.Errorf("Expected ErrTokenExpired, got: %v", err)
			}
			// A rule failure must not be reported as a bad signature.
			if errors.Is(err, paseto.ErrInvalidToken) {
				t.Errorf("Expected a claims error, not ErrInvalidToken: %v", err)
			}
		})
	}
}

// TestDecodeWithValidationRejectsNotYetValidToken covers the opt-in nbf rule.
func TestDecodeWithValidationRejectsNotYetValidToken(t *testing.T) {
	for _, c := range validationCases(t) {
		t.Run(c.name, func(t *testing.T) {
			token := encodeWith(t, c, payloadWithNbf(time.Hour))

			_, err := c.newCodec(t, validating()).Decode(token)
			if err == nil {
				t.Fatal("Expected an error for a not-yet-valid token")
			}
			if !errors.Is(err, paseto.ErrClaimsNotValid) {
				t.Errorf("Expected ErrClaimsNotValid, got: %v", err)
			}
			if !errors.Is(err, paseto.ErrTokenNotYetValid) {
				t.Errorf("Expected ErrTokenNotYetValid, got: %v", err)
			}
		})
	}
}

// TestDecodeWithValidationAcceptsValidTokens checks the two passing cases: a
// token still within its window, and one carrying no time claims at all. The
// latter is the deliberate difference from go-paseto's own NotExpired rule,
// which treats an absent exp as a failure.
func TestDecodeWithValidationAcceptsValidTokens(t *testing.T) {
	payloads := map[string]string{
		"within its validity window": fmt.Sprintf(
			`{"email":"user@example.com","nbf":%d,"exp":%d}`,
			time.Now().Add(-time.Hour).Unix(), time.Now().Add(time.Hour).Unix()),
		"without time claims": `{"email":"user@example.com"}`,
	}

	for _, c := range validationCases(t) {
		t.Run(c.name, func(t *testing.T) {
			for name, payload := range payloads {
				token := encodeWith(t, c, payload)
				decoded, err := c.newCodec(t, validating()).Decode(token)
				if err != nil {
					t.Fatalf("Expected token %s to decode, got: %v", name, err)
				}
				if !strings.Contains(decoded, "user@example.com") {
					t.Errorf("Expected claims in output, got: %s", decoded)
				}
			}
		})
	}
}

// TestClockSkew checks that the tolerance is applied on both ends of the window.
func TestClockSkew(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		skew    time.Duration
		wantErr error
	}{
		{"expired inside the tolerance", payloadWithExp(-time.Minute), 5 * time.Minute, nil},
		{"expired outside the tolerance", payloadWithExp(-time.Hour), 30 * time.Second, paseto.ErrTokenExpired},
		{"not yet valid inside the tolerance", payloadWithNbf(time.Minute), 5 * time.Minute, nil},
		{"not yet valid outside the tolerance", payloadWithNbf(time.Hour), 30 * time.Second, paseto.ErrTokenNotYetValid},
	}

	for _, c := range validationCases(t) {
		t.Run(c.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					token := encodeWith(t, c, tt.payload)
					decoder := c.newCodec(t, paseto.WithValidation(paseto.ValidationOptions{
						ValidateClaims: true,
						ClockSkew:      tt.skew,
					}))

					_, err := decoder.Decode(token)
					if tt.wantErr == nil {
						if err != nil {
							t.Fatalf("Expected the token to decode, got: %v", err)
						}
						return
					}
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("Expected %v, got: %v", tt.wantErr, err)
					}
				})
			}
		})
	}
}

// TestValidationOnPublicKeyDecoder checks the options reach the decoders built
// from a public key, which take a different constructor from the signing ones.
func TestValidationOnPublicKeyDecoder(t *testing.T) {
	edPrivate, edPublic := ed25519PEMKeyPair(t)
	p384Private, p384Public := p384PEMKeyPair(t, p384Key(t), true)

	tests := []struct {
		name    string
		encoder func() (paseto.EncoderDecoder, error)
		decoder func(opts ...paseto.Option) (paseto.EncoderDecoder, error)
	}{
		{
			"v4.public",
			func() (paseto.EncoderDecoder, error) { return paseto.NewPublicV4EncoderFromPrivateKey(edPrivate) },
			func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
				return paseto.NewPublicV4DecoderFromPublicKey(edPublic, opts...)
			},
		},
		{
			"v3.public",
			func() (paseto.EncoderDecoder, error) { return paseto.NewPublicV3EncoderFromPrivateKey(p384Private) },
			func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
				return paseto.NewPublicV3DecoderFromPublicKey(p384Public, opts...)
			},
		},
		{
			"v2.public",
			func() (paseto.EncoderDecoder, error) { return paseto.NewPublicV2EncoderFromPrivateKey(edPrivate) },
			func(opts ...paseto.Option) (paseto.EncoderDecoder, error) {
				return paseto.NewPublicV2DecoderFromPublicKey(edPublic, opts...)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder, err := tt.encoder()
			if err != nil {
				t.Fatalf("Failed to create encoder: %v", err)
			}
			token, err := encoder.Encode(payloadWithExp(-time.Hour))
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			decoder, err := tt.decoder(validating())
			if err != nil {
				t.Fatalf("Failed to create decoder: %v", err)
			}
			if _, err := decoder.Decode(token); !errors.Is(err, paseto.ErrTokenExpired) {
				t.Errorf("Expected ErrTokenExpired, got: %v", err)
			}

			decoder, err = tt.decoder()
			if err != nil {
				t.Fatalf("Failed to create decoder: %v", err)
			}
			if _, err := decoder.Decode(token); err != nil {
				t.Errorf("Expected the expired token to decode without validation, got: %v", err)
			}
		})
	}
}

// TestValidationRejectsUnusableTimeClaim covers a token minted elsewhere whose
// exp is not a timestamp at all. This package's Encode rejects such a payload,
// so the token has to be built with go-paseto directly.
func TestValidationRejectsUnusableTimeClaim(t *testing.T) {
	keyHex := localKeyHex(t)
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}
	key, err := gopaseto.V4SymmetricKeyFromBytes(keyBytes)
	if err != nil {
		t.Fatalf("Failed to build symmetric key: %v", err)
	}

	raw := gopaseto.NewToken()
	if err := raw.Set("exp", "yesterday"); err != nil {
		t.Fatalf("Failed to set exp: %v", err)
	}
	token := raw.V4Encrypt(key, nil)

	decoder, err := paseto.NewLocalV4Encoder(keyHex, validating())
	if err != nil {
		t.Fatalf("Failed to create decoder: %v", err)
	}

	_, err = decoder.Decode(token)
	if err == nil {
		t.Fatal("Expected an error for an unusable exp claim")
	}
	if !errors.Is(err, paseto.ErrInvalidClaim) {
		t.Errorf("Expected ErrInvalidClaim, got: %v", err)
	}
	if !errors.Is(err, paseto.ErrClaimsNotValid) {
		t.Errorf("Expected ErrClaimsNotValid, got: %v", err)
	}
}

// TestValidationDoesNotAffectEncode checks the option is decode-only: a codec
// built with validation still mints a token whose exp is already past.
func TestValidationDoesNotAffectEncode(t *testing.T) {
	for _, c := range validationCases(t) {
		t.Run(c.name, func(t *testing.T) {
			token, err := c.newCodec(t, validating()).Encode(payloadWithExp(-time.Hour))
			if err != nil {
				t.Fatalf("Expected encoding to succeed, got: %v", err)
			}
			if token == "" {
				t.Fatal("Expected a token")
			}
		})
	}
}
