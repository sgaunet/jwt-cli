package paseto_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

const validPayload = `{"name": "John Doe", "email": "john@example.com"}`
const invalidJSON = `{invalid json}`

func TestLocalV4EncoderDecoder(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	keyHex := hex.EncodeToString(key)

	t.Run("successful encode and decode", func(t *testing.T) {
		encoder, err := paseto.NewLocalV4Encoder(keyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if !strings.HasPrefix(token, "v4.local.") {
			t.Errorf("Expected token to start with 'v4.local.', got: %s", token)
		}

		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with invalid JSON", func(t *testing.T) {
		encoder, err := paseto.NewLocalV4Encoder(keyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		_, err = encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("decode with invalid token", func(t *testing.T) {
		encoder, err := paseto.NewLocalV4Encoder(keyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		_, err = encoder.Decode("invalid.token.here")
		if err == nil {
			t.Fatal("Expected error for invalid token")
		}
		if !strings.Contains(err.Error(), "invalid token") {
			t.Errorf("Expected invalid token error, got: %v", err)
		}
	})

	t.Run("decode with wrong key", func(t *testing.T) {
		encoder, err := paseto.NewLocalV4Encoder(keyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		wrongKey := make([]byte, 32)
		if _, err := rand.Read(wrongKey); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}
		wrongKeyHex := hex.EncodeToString(wrongKey)

		wrongEncoder, err := paseto.NewLocalV4Encoder(wrongKeyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder with wrong key: %v", err)
		}

		_, err = wrongEncoder.Decode(token)
		if err == nil {
			t.Fatal("Expected error when decoding with wrong key")
		}
	})

	t.Run("invalid key hex", func(t *testing.T) {
		_, err := paseto.NewLocalV4Encoder("invalid-hex")
		if err == nil {
			t.Fatal("Expected error for invalid hex")
		}
		if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})

	t.Run("wrong key size", func(t *testing.T) {
		shortKey := make([]byte, 16)
		if _, err := rand.Read(shortKey); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}
		shortKeyHex := hex.EncodeToString(shortKey)

		_, err := paseto.NewLocalV4Encoder(shortKeyHex)
		if err == nil {
			t.Fatal("Expected error for wrong key size")
		}
		if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})
}

func TestLocalV3EncoderDecoder(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	keyHex := hex.EncodeToString(key)

	t.Run("successful encode and decode", func(t *testing.T) {
		encoder, err := paseto.NewLocalV3Encoder(keyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if !strings.HasPrefix(token, "v3.local.") {
			t.Errorf("Expected token to start with 'v3.local.', got: %s", token)
		}

		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})
}

func TestLocalV2EncoderDecoder(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	keyHex := hex.EncodeToString(key)

	t.Run("successful encode and decode", func(t *testing.T) {
		encoder, err := paseto.NewLocalV2Encoder(keyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if !strings.HasPrefix(token, "v2.local.") {
			t.Errorf("Expected token to start with 'v2.local.', got: %s", token)
		}

		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})
}

func TestPublicV4EncoderDecoder(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	privateKeyHex := hex.EncodeToString(privateKey)

	t.Run("successful encode and decode with hex key", func(t *testing.T) {
		encoder, err := paseto.NewPublicV4EncoderFromHex(privateKeyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if !strings.HasPrefix(token, "v4.public.") {
			t.Errorf("Expected token to start with 'v4.public.', got: %s", token)
		}

		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("successful encode and decode with file keys", func(t *testing.T) {
		privateKeyFile := t.TempDir() + "/private.key"
		publicKeyFile := t.TempDir() + "/public.key"

		if err := os.WriteFile(privateKeyFile, privateKey, 0600); err != nil {
			t.Fatalf("Failed to write private key file: %v", err)
		}
		if err := os.WriteFile(publicKeyFile, publicKey, 0644); err != nil {
			t.Fatalf("Failed to write public key file: %v", err)
		}

		encoder, err := paseto.NewPublicV4EncoderFromPrivateKey(privateKeyFile)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder, err := paseto.NewPublicV4DecoderFromPublicKey(publicKeyFile)
		if err != nil {
			t.Fatalf("Failed to create decoder: %v", err)
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
		encoder, err := paseto.NewPublicV4EncoderFromHex(privateKeyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		_, err = encoder.Encode(invalidJSON)
		if err == nil {
			t.Fatal("Expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected JSON error, got: %v", err)
		}
	})

	t.Run("decode with invalid token", func(t *testing.T) {
		encoder, err := paseto.NewPublicV4EncoderFromHex(privateKeyHex)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}

		_, err = encoder.Decode("invalid.token.here")
		if err == nil {
			t.Fatal("Expected error for invalid token")
		}
		if !strings.Contains(err.Error(), "invalid token") {
			t.Errorf("Expected invalid token error, got: %v", err)
		}
	})

	t.Run("invalid key hex", func(t *testing.T) {
		_, err := paseto.NewPublicV4EncoderFromHex("invalid-hex")
		if err == nil {
			t.Fatal("Expected error for invalid hex")
		}
		if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})

	t.Run("wrong key size", func(t *testing.T) {
		shortKey := make([]byte, 16)
		if _, err := rand.Read(shortKey); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}
		shortKeyHex := hex.EncodeToString(shortKey)

		_, err := paseto.NewPublicV4EncoderFromHex(shortKeyHex)
		if err == nil {
			t.Fatal("Expected error for wrong key size")
		}
		if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})

	t.Run("non-existent key file", func(t *testing.T) {
		_, err := paseto.NewPublicV4EncoderFromPrivateKey("/non/existent/file")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "failed to read private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}

		_, err = paseto.NewPublicV4DecoderFromPublicKey("/non/existent/file")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		if !strings.Contains(err.Error(), "failed to read public key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})
}
