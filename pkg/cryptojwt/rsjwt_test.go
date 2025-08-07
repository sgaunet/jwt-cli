package cryptojwt_test

import (
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

func TestRS256EncoderDecoder(t *testing.T) {
	privateKeyPath, publicKeyPath := generateRSAKeyPair(t)

	t.Run("successful encode with private key", func(t *testing.T) {
		encoder := cryptojwt.NewRS256Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if token == "" {
			t.Fatal("Expected non-empty token")
		}
	})

	t.Run("successful decode with private key", func(t *testing.T) {
		encoder := cryptojwt.NewRS256Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewRS256DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("successful decode with public key", func(t *testing.T) {
		encoder := cryptojwt.NewRS256Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewRS256DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON", func(t *testing.T) {
		encoder := cryptojwt.NewRS256Encoder(privateKeyPath)
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("encode with non-existent private key file", func(t *testing.T) {
		encoder := cryptojwt.NewRS256Encoder(getNonExistentPath(t))
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent private key file", func(t *testing.T) {
		decoder := cryptojwt.NewRS256DecoderWithPrivateKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token.here")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent public key file", func(t *testing.T) {
		decoder := cryptojwt.NewRS256DecoderWithPublicKeyFile(getNonExistentPath(t))
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
		encoder := cryptojwt.NewRS256Encoder(invalidPEM)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "error parsing RSA private key") {
			t.Errorf("Expected PEM parse error, got: %v", err)
		}
	})

	t.Run("decode with invalid PEM public key", func(t *testing.T) {
		invalidPEM := createInvalidPEMFile(t)
		decoder := cryptojwt.NewRS256DecoderWithPublicKeyFile(invalidPEM)
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "error parsing RSA public key") {
			t.Errorf("Expected PEM parse error, got: %v", err)
		}
	})

	t.Run("encode with malformed RSA key", func(t *testing.T) {
		malformedKey := createMalformedRSAKeyFile(t)
		encoder := cryptojwt.NewRS256Encoder(malformedKey)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for malformed RSA key")
		}
		if !strings.Contains(err.Error(), "error parsing RSA private key") {
			t.Errorf("Expected RSA parse error, got: %v", err)
		}
	})

	t.Run("decode with invalid token", func(t *testing.T) {
		decoder := cryptojwt.NewRS256DecoderWithPublicKeyFile(publicKeyPath)
		_, err := decoder.Decode("invalid.token.here")
		if err == nil {
			t.Fatal("Expected error for invalid token")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})
}

func TestRS384EncoderDecoder(t *testing.T) {
	privateKeyPath, publicKeyPath := generateRSAKeyPair(t)

	t.Run("successful encode and decode with RS384", func(t *testing.T) {
		encoder := cryptojwt.NewRS384Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewRS384DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("decode with private key file RS384", func(t *testing.T) {
		encoder := cryptojwt.NewRS384Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewRS384DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with non-existent file RS384", func(t *testing.T) {
		encoder := cryptojwt.NewRS384Encoder(getNonExistentPath(t))
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent private key RS384", func(t *testing.T) {
		decoder := cryptojwt.NewRS384DecoderWithPrivateKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent public key RS384", func(t *testing.T) {
		decoder := cryptojwt.NewRS384DecoderWithPublicKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading public key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("invalid JSON in decode RS384", func(t *testing.T) {
		encoder := cryptojwt.NewRS384Encoder(privateKeyPath)
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})
}

func TestRS512EncoderDecoder(t *testing.T) {
	privateKeyPath, publicKeyPath := generateRSAKeyPair(t)

	t.Run("successful encode and decode with RS512", func(t *testing.T) {
		encoder := cryptojwt.NewRS512Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewRS512DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("decode with private key file RS512", func(t *testing.T) {
		encoder := cryptojwt.NewRS512Encoder(privateKeyPath)
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder := cryptojwt.NewRS512DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON RS512", func(t *testing.T) {
		encoder := cryptojwt.NewRS512Encoder(privateKeyPath)
		_, err := encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("encode with non-existent file RS512", func(t *testing.T) {
		encoder := cryptojwt.NewRS512Encoder(getNonExistentPath(t))
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent private key RS512", func(t *testing.T) {
		decoder := cryptojwt.NewRS512DecoderWithPrivateKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with non-existent public key RS512", func(t *testing.T) {
		decoder := cryptojwt.NewRS512DecoderWithPublicKeyFile(getNonExistentPath(t))
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "error reading public key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("decode with malformed token RS512", func(t *testing.T) {
		decoder := cryptojwt.NewRS512DecoderWithPublicKeyFile(publicKeyPath)
		_, err := decoder.Decode("not.a.jwt")
		if err == nil {
			t.Fatal("Expected error for malformed token")
		}
		if !strings.Contains(err.Error(), "failed to parse token") {
			t.Errorf("Expected parse error, got: %v", err)
		}
	})
}

func TestRSAKeyErrors(t *testing.T) {
	t.Run("invalid PEM format for private key decoder", func(t *testing.T) {
		invalidPEM := createInvalidPEMFile(t)
		decoder := cryptojwt.NewRS256DecoderWithPrivateKeyFile(invalidPEM)
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "error parsing RSA private key") {
			t.Errorf("Expected RSA parse error, got: %v", err)
		}
	})

	t.Run("malformed RSA private key", func(t *testing.T) {
		malformedKey := createMalformedRSAKeyFile(t)
		decoder := cryptojwt.NewRS384DecoderWithPrivateKeyFile(malformedKey)
		_, err := decoder.Decode("dummy.token")
		if err == nil {
			t.Fatal("Expected error for malformed RSA key")
		}
		if !strings.Contains(err.Error(), "error parsing RSA private key") {
			t.Errorf("Expected RSA parse error, got: %v", err)
		}
	})

	t.Run("wrong key type in PEM", func(t *testing.T) {
		wrongTypeKey := createWrongTypePEMFile(t, "CERTIFICATE")
		encoder := cryptojwt.NewRS512Encoder(wrongTypeKey)
		_, err := encoder.Encode(validPayload)
		if err == nil {
			t.Fatal("Expected error for wrong key type")
		}
		if !strings.Contains(err.Error(), "error parsing RSA private key") {
			t.Errorf("Expected RSA parse error, got: %v", err)
		}
	})
}

func TestRSAComplexPayloads(t *testing.T) {
	privateKeyPath, publicKeyPath := generateRSAKeyPair(t)

	t.Run("complex nested JSON", func(t *testing.T) {
		complexPayload := `{
			"sub": "1234567890",
			"roles": ["admin", "user"],
			"permissions": {
				"read": true,
				"write": true,
				"delete": false
			},
			"metadata": {
				"version": "1.0",
				"timestamp": 1516239022
			}
		}`

		encoder := cryptojwt.NewRS256Encoder(privateKeyPath)
		token, err := encoder.Encode(complexPayload)
		if err != nil {
			t.Fatalf("Failed to encode complex payload: %v", err)
		}

		decoder := cryptojwt.NewRS256DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "permissions") {
			t.Errorf("Expected decoded payload to contain permissions")
		}
	})

	t.Run("empty object payload", func(t *testing.T) {
		encoder := cryptojwt.NewRS384Encoder(privateKeyPath)
		token, err := encoder.Encode("{}")
		if err != nil {
			t.Fatalf("Failed to encode empty object: %v", err)
		}

		decoder := cryptojwt.NewRS384DecoderWithPrivateKeyFile(privateKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if decoded != "{}" {
			t.Errorf("Expected empty object, got: %s", decoded)
		}
	})

	t.Run("unicode characters in payload", func(t *testing.T) {
		unicodePayload := `{"name":"用户名","message":"Hello 世界"}`
		
		encoder := cryptojwt.NewRS512Encoder(privateKeyPath)
		token, err := encoder.Encode(unicodePayload)
		if err != nil {
			t.Fatalf("Failed to encode unicode payload: %v", err)
		}

		decoder := cryptojwt.NewRS512DecoderWithPublicKeyFile(publicKeyPath)
		decoded, err := decoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "世界") {
			t.Errorf("Expected decoded payload to contain unicode characters")
		}
	})
}