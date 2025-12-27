package cryptojwt_test

import (
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

func TestES256EncoderDecoder(t *testing.T) {
	privateKeyPath, publicKeyPath := generateECDSAKeyPair(t, elliptic.P256())

	t.Run("successful encode with private key", func(t *testing.T) {
		encoder := cryptojwt.NewES256Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if token == "" {
			t.Fatal("Expected non-empty token")
		}
	})

	t.Run("successful decode with private key", func(t *testing.T) {
		encoder := cryptojwt.NewES256Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewES256DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("successful decode with public key", func(t *testing.T) {
		encoder := cryptojwt.NewES256Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON", func(t *testing.T) {
		encoder := cryptojwt.NewES256Encoder(privateKeyPath)
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("encode with non-existent private key file", func(t *testing.T) {
		encoder := cryptojwt.NewES256Encoder(getNonExistentPath(t))
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent private key file", func(t *testing.T) {
		decoder := cryptojwt.NewES256DecoderWithPrivateKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token.here")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent public key file", func(t *testing.T) {
		decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token.here")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading public key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("encode with invalid PEM file", func(t *testing.T) {
		invalidPEM := createInvalidPEMFile(t)
		encoder := cryptojwt.NewES256Encoder(invalidPEM)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "unable to load key: PEM block is nil") {
			t.Errorf("Expected PEM error, got: %v", err)
		}
	})

	t.Run("decode with invalid PEM public key", func(t *testing.T) {
		invalidPEM := createInvalidPEMFile(t)
		decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(invalidPEM)
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "error parsing EC public key") {
			t.Errorf("Expected PEM parse error, got: %v", err)
		}
	})

	t.Run("encode with wrong key type", func(t *testing.T) {
		wrongTypeKey := createWrongTypePEMFile(t, "RSA PRIVATE KEY")
		encoder := cryptojwt.NewES256Encoder(wrongTypeKey)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for wrong key type")
		}
		if !strings.Contains(err.Error(), "wrong type of key") {
			t.Errorf("Expected wrong key type error, got: %v", err)
		}
	})

	t.Run("encode with malformed EC key", func(t *testing.T) {
		malformedKey := createMalformedECKeyFile(t)
		encoder := cryptojwt.NewES256Encoder(malformedKey)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for malformed EC key")
		}
		if !strings.Contains(err.Error(), "error parsing EC private key") {
			t.Errorf("Expected EC parse error, got: %v", err)
		}
	})

	t.Run("decode with invalid token", func(t *testing.T) {
		decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(publicKeyPath)
		_, err := decoder.Decode("invalid.token.here")
		if err == nil {
			t.Fatal("Expected error for invalid token")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})
}

func TestES384EncoderDecoder(t *testing.T) {
	privateKeyPath, publicKeyPath := generateECDSAKeyPair(t, elliptic.P384())

	t.Run("successful encode and decode with ES384", func(t *testing.T) {
		encoder := cryptojwt.NewES384Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewES384DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("decode with private key file ES384", func(t *testing.T) {
		encoder := cryptojwt.NewES384Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewES384DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with non-existent file ES384", func(t *testing.T) {
		encoder := cryptojwt.NewES384Encoder(getNonExistentPath(t))
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent private key ES384", func(t *testing.T) {
		decoder := cryptojwt.NewES384DecoderWithPrivateKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent public key ES384", func(t *testing.T) {
		decoder := cryptojwt.NewES384DecoderWithPublicKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading public key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("encode with wrong key type ES384", func(t *testing.T) {
		wrongTypeKey := createWrongTypePEMFile(t, "CERTIFICATE")
		encoder := cryptojwt.NewES384Encoder(wrongTypeKey)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for wrong key type")
		}
		if !strings.Contains(err.Error(), "wrong type of key") {
			t.Errorf("Expected wrong key type error, got: %v", err)
		}
	})

	t.Run("invalid JSON in decode ES384", func(t *testing.T) {
		encoder := cryptojwt.NewES384Encoder(privateKeyPath)
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})
}

func TestES512EncoderDecoder(t *testing.T) {
	privateKeyPath, publicKeyPath := generateECDSAKeyPair(t, elliptic.P521())

	t.Run("successful encode and decode with ES512", func(t *testing.T) {
		encoder := cryptojwt.NewES512Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewES512DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("decode with private key file ES512", func(t *testing.T) {
		encoder := cryptojwt.NewES512Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewES512DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON ES512", func(t *testing.T) {
		encoder := cryptojwt.NewES512Encoder(privateKeyPath)
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("encode with non-existent file ES512", func(t *testing.T) {
		encoder := cryptojwt.NewES512Encoder(getNonExistentPath(t))
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent private key ES512", func(t *testing.T) {
		decoder := cryptojwt.NewES512DecoderWithPrivateKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent public key ES512", func(t *testing.T) {
		decoder := cryptojwt.NewES512DecoderWithPublicKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading public key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with malformed token ES512", func(t *testing.T) {
		decoder := cryptojwt.NewES512DecoderWithPublicKeyFile(publicKeyPath)
		_, err := decoder.Decode("not.a.jwt")
		if err == nil {
			t.Fatal("Expected error for malformed token")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})

	t.Run("encode with malformed EC key ES512", func(t *testing.T) {
		malformedKey := createMalformedECKeyFile(t)
		encoder := cryptojwt.NewES512Encoder(malformedKey)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for malformed EC key")
		}
		if !strings.Contains(err.Error(), "error parsing EC private key") {
			t.Errorf("Expected EC parse error, got: %v", err)
		}
	})
}

func TestECDSAKeyErrors(t *testing.T) {
	t.Run("invalid PEM format for private key decoder", func(t *testing.T) {
		invalidPEM := createInvalidPEMFile(t)
		decoder := cryptojwt.NewES256DecoderWithPrivateKeyFile(invalidPEM)
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "unable to load key: PEM block is nil") {
			t.Errorf("Expected PEM error, got: %v", err)
		}
	})

	t.Run("malformed EC private key", func(t *testing.T) {
		malformedKey := createMalformedECKeyFile(t)
		decoder := cryptojwt.NewES384DecoderWithPrivateKeyFile(malformedKey)
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for malformed EC key")
		}
		if !strings.Contains(err.Error(), "error parsing EC private key") {
			t.Errorf("Expected EC parse error, got: %v", err)
		}
	})

	t.Run("wrong key type in PEM", func(t *testing.T) {
		wrongTypeKey := createWrongTypePEMFile(t, "RSA PRIVATE KEY")
		encoder := cryptojwt.NewES512Encoder(wrongTypeKey)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for wrong key type")
		}
		if !strings.Contains(err.Error(), "wrong type of key - expected EC PRIVATE KEY") {
			t.Errorf("Expected wrong key type error, got: %v", err)
		}
	})

	t.Run("invalid PEM for public key decoder", func(t *testing.T) {
		invalidPEM := createInvalidPEMFile(t)
		decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(invalidPEM)
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "error parsing EC public key") {
			t.Errorf("Expected PEM parse error, got: %v", err)
		}
	})
}

func TestECDSAComplexPayloads(t *testing.T) {
	t.Run("complex nested JSON", func(t *testing.T) {
		privateKeyPath, publicKeyPath := generateECDSAKeyPair(t, elliptic.P256())
		complexPayload := `{
			"sub": "1234567890",
			"email": "user@example.com",
			"scopes": ["read:users", "write:posts"],
			"settings": {
				"theme": "dark",
				"notifications": {
					"email": true,
					"push": false
				}
			},
			"exp": 1916239022
		}`

		encoder := cryptojwt.NewES256Encoder(privateKeyPath)
		token, err := encoder.Encode(complexPayload)
		if err != nil {
			t.Fatalf("Failed to encode complex payload: %v", err)
		}

		decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "notifications") {
			t.Errorf("Expected decoded payload to contain notifications")
		}
	})

	t.Run("empty object payload", func(t *testing.T) {
		privateKeyPath, _ := generateECDSAKeyPair(t, elliptic.P384())
		encoder := cryptojwt.NewES384Encoder(privateKeyPath)
		token, err := encoder.Encode("{}")
		if err != nil {
			t.Fatalf("Failed to encode empty object: %v", err)
		}

		decoder := cryptojwt.NewES384DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if decoded != "{}" {
			t.Errorf("Expected empty object, got: %s", decoded)
		}
	})

	t.Run("special characters in payload", func(t *testing.T) {
		privateKeyPath, publicKeyPath := generateECDSAKeyPair(t, elliptic.P521())
		specialPayload := `{"message":"Hello\nWorld\t!","emoji":"🔐"}`
		
		encoder := cryptojwt.NewES512Encoder(privateKeyPath)
		token, err := encoder.Encode(specialPayload)
		if err != nil {
			t.Fatalf("Failed to encode special payload: %v", err)
		}

		decoder := cryptojwt.NewES512DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "emoji") {
			t.Errorf("Expected decoded payload to contain emoji field")
		}
	})

	t.Run("large payload", func(t *testing.T) {
		privateKeyPath, publicKeyPath := generateECDSAKeyPair(t, elliptic.P256())
		largePayload := `{"data":[0,1,2,3,4,5,6,7,8,9],"more":"test data"}`

		encoder := cryptojwt.NewES256Encoder(privateKeyPath)
		token, err := encoder.Encode(largePayload)
		if err != nil {
			t.Fatalf("Failed to encode large payload: %v", err)
		}

		decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "data") {
			t.Errorf("Expected decoded payload to contain data field")
		}
	})
}

// Benchmarks comparing cached vs uncached performance

func BenchmarkES256EncodeWithoutCache(b *testing.B) {
	privateKeyPath, _ := generateECDSAKeyPair(b, elliptic.P256())
	encoder := cryptojwt.NewES256Encoder(privateKeyPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.Encode(validPayload)
	}
}

func BenchmarkES256EncodeWithCache(b *testing.B) {
	privateKeyPath, _ := generateECDSAKeyPair(b, elliptic.P256())
	encoder, err := cryptojwt.NewES256EncoderWithCache(privateKeyPath)
	if err != nil {
		b.Fatalf("Failed to create cached encoder: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.Encode(validPayload)
	}
}

func BenchmarkES256DecodeWithoutCache(b *testing.B) {
	privateKeyPath, publicKeyPath := generateECDSAKeyPair(b, elliptic.P256())
	encoder := cryptojwt.NewES256Encoder(privateKeyPath)
	token, err := encoder.Encode(validPayload)
	if err != nil {
		b.Fatalf("Failed to encode: %v", err)
	}
	decoder := cryptojwt.NewES256DecoderWithPublicKeyFile(publicKeyPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decoder.Decode(token)
	}
}

func BenchmarkES256DecodeWithCache(b *testing.B) {
	privateKeyPath, publicKeyPath := generateECDSAKeyPair(b, elliptic.P256())
	encoder := cryptojwt.NewES256Encoder(privateKeyPath)
	token, err := encoder.Encode(validPayload)
	if err != nil {
		b.Fatalf("Failed to encode: %v", err)
	}
	decoder, err := cryptojwt.NewES256DecoderWithPublicKeyFileAndCache(publicKeyPath)
	if err != nil {
		b.Fatalf("Failed to create cached decoder: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decoder.Decode(token)
	}
}