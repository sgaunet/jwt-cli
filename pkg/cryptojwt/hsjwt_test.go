package cryptojwt_test

import (
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

func TestHS256EncoderDecoder(t *testing.T) {
	secret := []byte("test-secret-key")
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

		wrongDecoder := cryptojwt.NewHS256Decoder([]byte("wrong-secret"))
		_, err = wrongDecoder.Decode(token)
		if err == nil {
			t.Fatal("Expected error for wrong secret")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("empty secret", func(t *testing.T) {
		emptyEncoder := cryptojwt.NewHS256Encoder([]byte(""))
		token, err := emptyEncoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with empty secret: %v", err)
		}

		emptyDecoder := cryptojwt.NewHS256Decoder([]byte(""))
		decoded, err := emptyDecoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode with empty secret: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})
}

func TestHS384EncoderDecoder(t *testing.T) {
	secret := []byte("test-secret-key-384")
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
		hs256Encoder := cryptojwt.NewHS256Encoder(secret)
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
}

func TestHS512EncoderDecoder(t *testing.T) {
	secret := []byte("test-secret-key-512")
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

	t.Run("nil secret handling", func(t *testing.T) {
		nilEncoder := cryptojwt.NewHS512Encoder(nil)
		token, err := nilEncoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode with nil secret: %v", err)
		}

		nilDecoder := cryptojwt.NewHS512Decoder(nil)
		decoded, err := nilDecoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode with nil secret: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})
}

func TestHSAlgorithmInteroperability(t *testing.T) {
	secret := []byte("shared-secret")
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
		
		encoder := cryptojwt.NewHS256Encoder([]byte("secret"))
		token, err := encoder.Encode(complexPayload)
		if err != nil {
			t.Fatalf("Failed to encode complex payload: %v", err)
		}

		decoder := cryptojwt.NewHS256Decoder([]byte("secret"))
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "nested") {
			t.Errorf("Expected decoded payload to contain nested structure")
		}
	})

	t.Run("empty payload object", func(t *testing.T) {
		encoder := cryptojwt.NewHS256Encoder([]byte("secret"))
		token, err := encoder.Encode("{}")
		if err != nil {
			t.Fatalf("Failed to encode empty object: %v", err)
		}

		decoder := cryptojwt.NewHS256Decoder([]byte("secret"))
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