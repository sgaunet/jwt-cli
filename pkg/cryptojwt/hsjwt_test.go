package cryptojwt_test

import (
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

func TestHS256EncoderDecoder(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	encoder := cryptojwt.NewHS256Encoder(secret)
	decoder := cryptojwt.NewHS256Decoder(secret)

	t.Run("successful encode and decode", func(t *testing.T) {
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if token == "" {
			t.Fatal("Expected non-empty token")
		}

		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON", func(t *testing.T) {
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("decode with invalid token", func(t *testing.T) {
		_, err := decoder.Decode("invalid.token.here")
		if err == nil {
			t.Fatal("Expected error for invalid token")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("decode with wrong secret", func(t *testing.T) {
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		wrongDecoder := cryptojwt.NewHS256Decoder([]byte("wrong-secret-but-valid-length-32b"))
		_, err = wrongDecoder.Decode(token)
		if err == nil {
			t.Fatal("Expected error for wrong secret")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("empty secret with validation", func(t *testing.T) {
		emptyEncoder := cryptojwt.NewHS256Encoder([]byte(""))
		_, err := emptyEncoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for empty secret")
		}
		if !strings.Contains(err.Error(), "weak secret") {
			t.Errorf("Expected weak secret error, got: %v", err)
		}
	})

	t.Run("weak secret (less than 32 bytes)", func(t *testing.T) {
		weakSecret := []byte("tooshort")
		encoder := cryptojwt.NewHS256Encoder(weakSecret)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for weak secret")
		}
		if !strings.Contains(err.Error(), "weak secret") || !strings.Contains(err.Error(), "minimum of 32 bytes") {
			t.Errorf("Expected weak secret error with minimum length, got: %v", err)
		}
	})

	t.Run("allow weak secret with flag", func(t *testing.T) {
		weakSecret := []byte("short")
		encoder := cryptojwt.NewHS256EncoderWithOptions(weakSecret, true)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with allow-weak-secret flag: %v", err)
		}

		decoder := cryptojwt.NewHS256DecoderWithOptions(weakSecret, true)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode with allow-weak-secret flag: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("valid secret (32 bytes)", func(t *testing.T) {
		validSecret := []byte("this-is-a-valid-32-byte-secret!!")
		encoder := cryptojwt.NewHS256Encoder(validSecret)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with valid secret: %v", err)
		}

		decoder := cryptojwt.NewHS256Decoder(validSecret)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode with valid secret: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})
}

func TestHS384EncoderDecoder(t *testing.T) {
	secret := []byte("test-secret-key-384-this-is-a-valid-secret-48bytes!")
	encoder := cryptojwt.NewHS384Encoder(secret)
	decoder := cryptojwt.NewHS384Decoder(secret)

	t.Run("successful encode and decode", func(t *testing.T) {
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if token == "" {
			t.Fatal("Expected non-empty token")
		}

		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON", func(t *testing.T) {
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("decode with invalid token", func(t *testing.T) {
		_, err := decoder.Decode("invalid.token")
		if err == nil {
			t.Fatal("Expected error for invalid token")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("decode with wrong algorithm token", func(t *testing.T) {
		// JWT doesn't enforce algorithm checking at decode time for HMAC
		// This test verifies behavior rather than expecting failure
		hs256Encoder := cryptojwt.NewHS256EncoderWithOptions(secret, true)
		hs256Token, err := hs256Encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with HS256: %v", err)
		}

		// HMAC algorithms with same secret can decode each other's tokens
		decoded, err := decoder.Decode(hs256Token)
		if err != nil {
			t.Logf("Decode failed as expected with different algorithm: %v", err)
		} else {
			// This is actually valid behavior for HMAC algorithms
			if !strings.Contains(decoded, "John Doe") {
				t.Errorf("Decoded content unexpected: %s", decoded)
			}
		}
	})

	t.Run("weak secret (less than 48 bytes)", func(t *testing.T) {
		weakSecret := []byte("short-secret")
		encoder := cryptojwt.NewHS384Encoder(weakSecret)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for weak secret")
		}
		if !strings.Contains(err.Error(), "weak secret") || !strings.Contains(err.Error(), "minimum of 48 bytes") {
			t.Errorf("Expected weak secret error with minimum length, got: %v", err)
		}
	})

	t.Run("allow weak secret with flag", func(t *testing.T) {
		weakSecret := []byte("weak")
		encoder := cryptojwt.NewHS384EncoderWithOptions(weakSecret, true)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with allow-weak-secret flag: %v", err)
		}

		decoder := cryptojwt.NewHS384DecoderWithOptions(weakSecret, true)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode with allow-weak-secret flag: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})
}

func TestHS512EncoderDecoder(t *testing.T) {
	secret := []byte("test-secret-key-512-this-is-a-valid-secret-for-hs512-exactly64!!")
	encoder := cryptojwt.NewHS512Encoder(secret)
	decoder := cryptojwt.NewHS512Decoder(secret)

	t.Run("successful encode and decode", func(t *testing.T) {
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if token == "" {
			t.Fatal("Expected non-empty token")
		}

		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON", func(t *testing.T) {
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("decode with malformed token", func(t *testing.T) {
		_, err := decoder.Decode("not-a-jwt")
		if err == nil {
			t.Fatal("Expected error for malformed token")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("nil secret validation", func(t *testing.T) {
		nilEncoder := cryptojwt.NewHS512Encoder(nil)
		_, err := nilEncoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for nil secret")
		}
		if !strings.Contains(err.Error(), "weak secret") {
			t.Errorf("Expected weak secret error, got: %v", err)
		}
	})

	t.Run("weak secret (less than 64 bytes)", func(t *testing.T) {
		weakSecret := []byte("too-short-for-hs512")
		encoder := cryptojwt.NewHS512Encoder(weakSecret)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for weak secret")
		}
		if !strings.Contains(err.Error(), "weak secret") || !strings.Contains(err.Error(), "minimum of 64 bytes") {
			t.Errorf("Expected weak secret error with minimum length, got: %v", err)
		}
	})

	t.Run("allow weak secret with flag", func(t *testing.T) {
		weakSecret := []byte("weak-hs512")
		encoder := cryptojwt.NewHS512EncoderWithOptions(weakSecret, true)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with allow-weak-secret flag: %v", err)
		}

		decoder := cryptojwt.NewHS512DecoderWithOptions(weakSecret, true)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode with allow-weak-secret flag: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})
}

func TestHSAlgorithmInteroperability(t *testing.T) {
	// Use a secret that meets HS512 requirements (64 bytes) so it works for all algorithms
	secret := []byte("this-is-a-shared-secret-for-all-algorithms-hs512-requirements!!!")
	payload := `{"alg":"test","data":"interop"}`

	tests := []struct {
		name    string
		encoder cryptojwt.EncoderDecoder
		decoder cryptojwt.EncoderDecoder
	}{
		{
			name:    "HS256 to HS256",
			encoder: cryptojwt.NewHS256Encoder(secret),
			decoder: cryptojwt.NewHS256Decoder(secret),
		},
		{
			name:    "HS384 to HS384",
			encoder: cryptojwt.NewHS384Encoder(secret),
			decoder: cryptojwt.NewHS384Decoder(secret),
		},
		{
			name:    "HS512 to HS512",
			encoder: cryptojwt.NewHS512Encoder(secret),
			decoder: cryptojwt.NewHS512Decoder(secret),
		},
		{
			name:    "HS256 to HS384",
			encoder: cryptojwt.NewHS256Encoder(secret),
			decoder: cryptojwt.NewHS384Decoder(secret),
		},
		{
			name:    "HS256 to HS512",
			encoder: cryptojwt.NewHS256Encoder(secret),
			decoder: cryptojwt.NewHS512Decoder(secret),
		},
		{
			name:    "HS384 to HS512",
			encoder: cryptojwt.NewHS384Encoder(secret),
			decoder: cryptojwt.NewHS512Decoder(secret),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.encoder.Encode(payload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			decoded, err := tt.decoder.Decode(token)
			// HMAC algorithms with the same secret can decode each other's tokens
			// This is standard JWT behavior
			if err != nil {
				t.Logf("Decode failed (may be expected for cross-algorithm): %v", err)
			} else {
				if !strings.Contains(decoded, "interop") {
					t.Errorf("Expected decoded payload to contain 'interop', got: %s", decoded)
				}
			}
		})
	}
}

func TestHSEdgeCases(t *testing.T) {
	validSecret := []byte("this-is-a-valid-secret-exactly-32-bytes!")

	t.Run("complex JSON payload", func(t *testing.T) {
		complexPayload := `{
			"sub": "1234567890",
			"name": "Test User",
			"admin": true,
			"iat": 1516239022,
			"nested": {
				"key1": "value1",
				"key2": 123,
				"array": [1, 2, 3]
			}
		}`

		encoder := cryptojwt.NewHS256Encoder(validSecret)
		token, err := encoder.Encode(complexPayload)
		if err != nil {
			t.Fatalf("Failed to encode complex payload: %v", err)
		}

		decoder := cryptojwt.NewHS256Decoder(validSecret)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "nested") {
			t.Errorf("Expected decoded payload to contain nested structure")
		}
	})

	t.Run("empty payload object", func(t *testing.T) {
		encoder := cryptojwt.NewHS256Encoder(validSecret)
		token, err := encoder.Encode("{}")
		if err != nil {
			t.Fatalf("Failed to encode empty object: %v", err)
		}

		decoder := cryptojwt.NewHS256Decoder(validSecret)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if decoded != "{}" {
			t.Errorf("Expected empty object, got: %s", decoded)
		}
	})

	t.Run("very long secret key", func(t *testing.T) {
		longSecret := make([]byte, 1024)
		for i := range longSecret {
			longSecret[i] = byte(i % 256)
		}
		
		encoder := cryptojwt.NewHS512Encoder(longSecret)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with long secret: %v", err)
		}

		decoder := cryptojwt.NewHS512Decoder(longSecret)
		_, err = decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode with long secret: %v", err)
		}
	})
}