package paseto_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

// writePEM writes a PEM block of the given type to a file in a temp dir and
// returns its path.
func writePEM(t *testing.T, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("Failed to write %s: %v", name, err)
	}
	return path
}

// writeRaw writes raw bytes to a file in a temp dir and returns its path.
func writeRaw(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("Failed to write %s: %v", name, err)
	}
	return path
}

// ed25519PEMKeyPair generates an Ed25519 key pair as PKCS#8 and PKIX PEM files.
func ed25519PEMKeyPair(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal Ed25519 private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal Ed25519 public key: %v", err)
	}
	return writePEM(t, "private.pem", "PRIVATE KEY", privDER),
		writePEM(t, "public.pem", "PUBLIC KEY", pubDER)
}

// p384Key generates a NIST P-384 key pair for PASETO V3 tests.
func p384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-384 key: %v", err)
	}
	return key
}

// p384PEMKeyPair writes a P-384 key pair as PEM files. When sec1 is true the
// private key uses the SEC 1 "EC PRIVATE KEY" encoding produced by
// "openssl ecparam -genkey"; otherwise it uses PKCS#8.
func p384PEMKeyPair(t *testing.T, key *ecdsa.PrivateKey, sec1 bool) (string, string) {
	t.Helper()
	var (
		privDER []byte
		err     error
		typ     string
	)
	if sec1 {
		privDER, err = x509.MarshalECPrivateKey(key)
		typ = "EC PRIVATE KEY"
	} else {
		privDER, err = x509.MarshalPKCS8PrivateKey(key)
		typ = "PRIVATE KEY"
	}
	if err != nil {
		t.Fatalf("Failed to marshal P-384 private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal P-384 public key: %v", err)
	}
	return writePEM(t, "private.pem", typ, privDER),
		writePEM(t, "public.pem", "PUBLIC KEY", pubDER)
}

func TestPublicV3EncoderDecoder(t *testing.T) {
	key := p384Key(t)

	// Both PEM encodings OpenSSL can produce must round-trip. The SEC 1 form is
	// what "jwt-cli paseto genkeys v3" instructs users to generate.
	for _, tc := range []struct {
		name string
		sec1 bool
	}{
		{"successful encode and decode with SEC 1 PEM keys", true},
		{"successful encode and decode with PKCS#8 PEM keys", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			privateKeyFile, publicKeyFile := p384PEMKeyPair(t, key, tc.sec1)

			encoder, err := paseto.NewPublicV3EncoderFromPrivateKey(privateKeyFile)
			if err != nil {
				t.Fatalf("Failed to create encoder: %v", err)
			}

			token, err := encoder.Encode(validPayload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}
			if !strings.HasPrefix(token, "v3.public.") {
				t.Errorf("Expected token to start with 'v3.public.', got: %s", token)
			}

			decoder, err := paseto.NewPublicV3DecoderFromPublicKey(publicKeyFile)
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
	}

	t.Run("decode with private key", func(t *testing.T) {
		privateKeyFile, _ := p384PEMKeyPair(t, key, true)

		encoder, err := paseto.NewPublicV3EncoderFromPrivateKey(privateKeyFile)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		decoded, err := encoder.Decode(token)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
		if !strings.Contains(decoded, "John Doe") {
			t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
		}
	})

	t.Run("encode with decoder built from public key", func(t *testing.T) {
		_, publicKeyFile := p384PEMKeyPair(t, key, true)

		decoder, err := paseto.NewPublicV3DecoderFromPublicKey(publicKeyFile)
		if err != nil {
			t.Fatalf("Failed to create decoder: %v", err)
		}
		if _, err := decoder.Encode(validPayload); err == nil {
			t.Fatal("Expected error when encoding without a private key")
		} else if !strings.Contains(err.Error(), "private key required") {
			t.Errorf("Expected private key required error, got: %v", err)
		}
	})

	t.Run("wrong curve is rejected", func(t *testing.T) {
		wrongCurve, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate P-256 key: %v", err)
		}
		der, err := x509.MarshalECPrivateKey(wrongCurve)
		if err != nil {
			t.Fatalf("Failed to marshal P-256 key: %v", err)
		}
		file := writePEM(t, "p256.pem", "EC PRIVATE KEY", der)

		if _, err := paseto.NewPublicV3EncoderFromPrivateKey(file); err == nil {
			t.Fatal("Expected error for non-P-384 curve")
		} else if !strings.Contains(err.Error(), "P-384") {
			t.Errorf("Expected P-384 curve error, got: %v", err)
		}
	})

	t.Run("decode with wrong key", func(t *testing.T) {
		privateKeyFile, _ := p384PEMKeyPair(t, key, true)
		encoder, err := paseto.NewPublicV3EncoderFromPrivateKey(privateKeyFile)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		_, otherPublicKeyFile := p384PEMKeyPair(t, p384Key(t), true)
		decoder, err := paseto.NewPublicV3DecoderFromPublicKey(otherPublicKeyFile)
		if err != nil {
			t.Fatalf("Failed to create decoder: %v", err)
		}
		if _, err := decoder.Decode(token); err == nil {
			t.Fatal("Expected error when decoding with the wrong key")
		}
	})

	t.Run("wrong PEM block type", func(t *testing.T) {
		file := writePEM(t, "cert.pem", "CERTIFICATE", []byte("not a key"))
		if _, err := paseto.NewPublicV3DecoderFromPublicKey(file); err == nil {
			t.Fatal("Expected error for wrong PEM block type")
		} else if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})

	t.Run("non-existent key file", func(t *testing.T) {
		if _, err := paseto.NewPublicV3EncoderFromPrivateKey("/non/existent/file"); err == nil {
			t.Fatal("Expected error for non-existent file")
		} else if !strings.Contains(err.Error(), "failed to read private key file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})
}

func TestPublicV2EncoderDecoder(t *testing.T) {
	t.Run("successful encode and decode with PEM keys", func(t *testing.T) {
		privateKeyFile, publicKeyFile := ed25519PEMKeyPair(t)

		encoder, err := paseto.NewPublicV2EncoderFromPrivateKey(privateKeyFile)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}
		if !strings.HasPrefix(token, "v2.public.") {
			t.Errorf("Expected token to start with 'v2.public.', got: %s", token)
		}

		decoder, err := paseto.NewPublicV2DecoderFromPublicKey(publicKeyFile)
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

	t.Run("successful encode and decode with raw keys", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		privateKeyFile := writeRaw(t, "private.key", privateKey)
		publicKeyFile := writeRaw(t, "public.key", publicKey)

		encoder, err := paseto.NewPublicV2EncoderFromPrivateKey(privateKeyFile)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		decoder, err := paseto.NewPublicV2DecoderFromPublicKey(publicKeyFile)
		if err != nil {
			t.Fatalf("Failed to create decoder: %v", err)
		}
		if _, err := decoder.Decode(token); err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}
	})

	t.Run("encode with invalid JSON", func(t *testing.T) {
		privateKeyFile, _ := ed25519PEMKeyPair(t)
		encoder, err := paseto.NewPublicV2EncoderFromPrivateKey(privateKeyFile)
		if err != nil {
			t.Fatalf("Failed to create encoder: %v", err)
		}
		if _, err := encoder.Encode(invalidJSON); err == nil {
			t.Fatal("Expected error for invalid JSON")
		} else if !strings.Contains(err.Error(), "payload is not a valid JSON") {
			t.Errorf("Expected invalid payload error, got: %v", err)
		}
	})

	t.Run("encode with decoder built from public key", func(t *testing.T) {
		_, publicKeyFile := ed25519PEMKeyPair(t)
		decoder, err := paseto.NewPublicV2DecoderFromPublicKey(publicKeyFile)
		if err != nil {
			t.Fatalf("Failed to create decoder: %v", err)
		}
		if _, err := decoder.Encode(validPayload); err == nil {
			t.Fatal("Expected error when encoding without a private key")
		} else if !strings.Contains(err.Error(), "private key required") {
			t.Errorf("Expected private key required error, got: %v", err)
		}
	})

	t.Run("wrong PEM block type", func(t *testing.T) {
		file := writePEM(t, "cert.pem", "CERTIFICATE", []byte("not a key"))
		if _, err := paseto.NewPublicV2EncoderFromPrivateKey(file); err == nil {
			t.Fatal("Expected error for wrong PEM block type")
		} else if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})

	t.Run("non-Ed25519 PEM key", func(t *testing.T) {
		key := p384Key(t)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("Failed to marshal P-384 key: %v", err)
		}
		file := writePEM(t, "ec.pem", "PRIVATE KEY", der)

		if _, err := paseto.NewPublicV2EncoderFromPrivateKey(file); err == nil {
			t.Fatal("Expected error for non-Ed25519 key")
		} else if !strings.Contains(err.Error(), "not Ed25519") {
			t.Errorf("Expected not-Ed25519 error, got: %v", err)
		}
	})
}

func TestPublicV4PEMKeys(t *testing.T) {
	// The pre-existing V4 test only exercises raw key bytes, leaving the PEM
	// parsing branch untested.
	t.Run("successful encode and decode with PEM keys", func(t *testing.T) {
		privateKeyFile, publicKeyFile := ed25519PEMKeyPair(t)

		encoder, err := paseto.NewPublicV4EncoderFromPrivateKey(privateKeyFile)
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

	t.Run("malformed PEM is treated as raw and rejected", func(t *testing.T) {
		file := writeRaw(t, "bad.pem", []byte("-----BEGIN PRIVATE KEY-----\nnot base64\n"))
		if _, err := paseto.NewPublicV4EncoderFromPrivateKey(file); err == nil {
			t.Fatal("Expected error for malformed PEM")
		} else if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})

	t.Run("wrong PEM block type", func(t *testing.T) {
		file := writePEM(t, "cert.pem", "CERTIFICATE", []byte("not a key"))
		if _, err := paseto.NewPublicV4DecoderFromPublicKey(file); err == nil {
			t.Fatal("Expected error for wrong PEM block type")
		} else if !strings.Contains(err.Error(), "invalid key") {
			t.Errorf("Expected invalid key error, got: %v", err)
		}
	})
}
