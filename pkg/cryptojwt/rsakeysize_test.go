package cryptojwt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

const weakRSAKeyBits = 1024

// rsAlgorithm bundles the three constructor flavours of one RS* algorithm so the
// key-size tests can run the same assertions against RS256, RS384 and RS512.
type rsAlgorithm struct {
	name              string
	encoder           func(string, bool) cryptojwt.Encoder
	decoderPrivateKey func(string, cryptojwt.ValidationOptions, bool) cryptojwt.Decoder
	decoderPublicKey  func(string, cryptojwt.ValidationOptions, bool) cryptojwt.Decoder
}

func rsAlgorithms() []rsAlgorithm {
	return []rsAlgorithm{
		{
			name:              "RS256",
			encoder:           cryptojwt.NewRS256EncoderWithOptions,
			decoderPrivateKey: cryptojwt.NewRS256DecoderWithPrivateKeyFileAndOptions,
			decoderPublicKey:  cryptojwt.NewRS256DecoderWithPublicKeyFileAndOptions,
		},
		{
			name:              "RS384",
			encoder:           cryptojwt.NewRS384EncoderWithOptions,
			decoderPrivateKey: cryptojwt.NewRS384DecoderWithPrivateKeyFileAndOptions,
			decoderPublicKey:  cryptojwt.NewRS384DecoderWithPublicKeyFileAndOptions,
		},
		{
			name:              "RS512",
			encoder:           cryptojwt.NewRS512EncoderWithOptions,
			decoderPrivateKey: cryptojwt.NewRS512DecoderWithPrivateKeyFileAndOptions,
			decoderPublicKey:  cryptojwt.NewRS512DecoderWithPublicKeyFileAndOptions,
		},
	}
}

// assertWeakKeyError checks that err reports ErrWeakKey and names both the offending
// size and the floor, so the user knows what to regenerate.
func assertWeakKeyError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("Expected a weak-key error, got nil")
	}
	if !errors.Is(err, cryptojwt.ErrWeakKey) {
		t.Errorf("Expected errors.Is(err, ErrWeakKey), got: %v", err)
	}
	if !strings.Contains(err.Error(), "1024 bits") {
		t.Errorf("Expected error to name the key size, got: %v", err)
	}
	if !strings.Contains(err.Error(), "minimum 2048") {
		t.Errorf("Expected error to name the 2048-bit minimum, got: %v", err)
	}
}

func TestRSAKeyBelowMinimumIsRejected(t *testing.T) {
	weakPrivateKey, weakPublicKey := generateRSAKeyPairWithBits(t, weakRSAKeyBits)

	for _, alg := range rsAlgorithms() {
		t.Run(alg.name+"/encode", func(t *testing.T) {
			_, err := alg.encoder(weakPrivateKey, false).Encode(`{"user":"alice"}`)
			assertWeakKeyError(t, err)
		})

		t.Run(alg.name+"/decode with private key", func(t *testing.T) {
			// A weak key is rejected before the token is even parsed, so any
			// syntactically valid token exercises the same path.
			token := encodeWithWeakRSAKey(t, alg, weakPrivateKey)
			_, err := alg.decoderPrivateKey(weakPrivateKey, cryptojwt.ValidationOptions{}, false).Decode(token)
			assertWeakKeyError(t, err)
		})

		t.Run(alg.name+"/decode with public key", func(t *testing.T) {
			token := encodeWithWeakRSAKey(t, alg, weakPrivateKey)
			_, err := alg.decoderPublicKey(weakPublicKey, cryptojwt.ValidationOptions{}, false).Decode(token)
			assertWeakKeyError(t, err)
		})
	}
}

func TestRSAKeyBelowMinimumIsAllowedWithOptOut(t *testing.T) {
	weakPrivateKey, weakPublicKey := generateRSAKeyPairWithBits(t, weakRSAKeyBits)
	const payload = `{"user":"alice"}`

	for _, alg := range rsAlgorithms() {
		t.Run(alg.name, func(t *testing.T) {
			token, err := alg.encoder(weakPrivateKey, true).Encode(payload)
			if err != nil {
				t.Fatalf("Failed to encode with allowWeakKey=true: %v", err)
			}

			claims, err := alg.decoderPrivateKey(weakPrivateKey, cryptojwt.ValidationOptions{}, true).Decode(token)
			if err != nil {
				t.Fatalf("Failed to decode with private key and allowWeakKey=true: %v", err)
			}
			if !strings.Contains(claims, `"alice"`) {
				t.Errorf("Expected claims to round-trip the payload, got: %s", claims)
			}

			claims, err = alg.decoderPublicKey(weakPublicKey, cryptojwt.ValidationOptions{}, true).Decode(token)
			if err != nil {
				t.Fatalf("Failed to decode with public key and allowWeakKey=true: %v", err)
			}
			if !strings.Contains(claims, `"alice"`) {
				t.Errorf("Expected claims to round-trip the payload, got: %s", claims)
			}
		})
	}
}

// TestRSAKeyAtMinimumIsAccepted guards the boundary: a key exactly at the floor
// must still work through the default constructors.
func TestRSAKeyAtMinimumIsAccepted(t *testing.T) {
	privateKeyPath, publicKeyPath := generateRSAKeyPair(t)

	token, err := cryptojwt.NewRS256Encoder(privateKeyPath).Encode(`{"user":"alice"}`)
	if err != nil {
		t.Fatalf("Failed to encode with a 2048-bit key: %v", err)
	}
	if _, err := cryptojwt.NewRS256DecoderWithPublicKeyFile(publicKeyPath).Decode(token); err != nil {
		t.Fatalf("Failed to decode with a 2048-bit key: %v", err)
	}
}

// encodeWithWeakRSAKey produces a token signed with a below-minimum key by taking
// the explicit opt-out, so the decode tests have something realistic to reject.
func encodeWithWeakRSAKey(t *testing.T, alg rsAlgorithm, privateKeyPath string) string {
	t.Helper()
	token, err := alg.encoder(privateKeyPath, true).Encode(`{"user":"alice"}`)
	if err != nil {
		t.Fatalf("Failed to prepare a token signed with a weak key: %v", err)
	}
	return token
}
