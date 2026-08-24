package cryptojwt_test

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// pinningPayload is the payload used by every algorithm pinning test.
const pinningPayload = `{"user":"alice","data":"pinning"}`

// assertAlgRejected asserts that err is the parser refusing tokenAlg because the
// decoder pinned a different algorithm. The message check distinguishes a rejection
// by jwt.WithValidMethods from an ordinary signature mismatch, so the test fails if
// the pinning is removed even when the signature would not have verified either.
func assertAlgRejected(t *testing.T, err error, tokenAlg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected token with alg=%s to be rejected, but it decoded successfully", tokenAlg)
	}
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Errorf("expected error to wrap jwt.ErrTokenSignatureInvalid, got: %v", err)
	}
	want := fmt.Sprintf("signing method %s is invalid", tokenAlg)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("expected error to mention %q, got: %v", want, err)
	}
}

// assertDecodes asserts the token decodes and carries the expected payload.
func assertDecodes(t *testing.T, decoded string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected token to decode, got error: %v", err)
	}
	if !strings.Contains(decoded, "pinning") {
		t.Errorf("expected decoded claims to contain 'pinning', got: %s", decoded)
	}
}

// TestHSAlgorithmPinning verifies that each HMAC decoder accepts only its own
// algorithm. All three share one secret, so without jwt.WithValidMethods every
// cross-algorithm pair would verify successfully.
func TestHSAlgorithmPinning(t *testing.T) {
	// 64 bytes satisfies the minimum secret length of HS256, HS384 and HS512.
	secret := []byte("this-is-a-shared-secret-for-all-algorithms-hs512-requirements!!!")

	encoders := map[string]cryptojwt.EncoderDecoder{
		"HS256": cryptojwt.NewHS256Encoder(secret),
		"HS384": cryptojwt.NewHS384Encoder(secret),
		"HS512": cryptojwt.NewHS512Encoder(secret),
	}
	decoders := map[string]cryptojwt.EncoderDecoder{
		"HS256": cryptojwt.NewHS256Decoder(secret),
		"HS384": cryptojwt.NewHS384Decoder(secret),
		"HS512": cryptojwt.NewHS512Decoder(secret),
	}

	for _, tokenAlg := range []string{"HS256", "HS384", "HS512"} {
		token, err := encoders[tokenAlg].Encode(pinningPayload)
		if err != nil {
			t.Fatalf("Failed to encode %s token: %v", tokenAlg, err)
		}
		for _, decoderAlg := range []string{"HS256", "HS384", "HS512"} {
			t.Run(tokenAlg+" token to "+decoderAlg+" decoder", func(t *testing.T) {
				decoded, err := decoders[decoderAlg].Decode(token)
				if tokenAlg == decoderAlg {
					assertDecodes(t, decoded, err)
					return
				}
				assertAlgRejected(t, err, tokenAlg)
			})
		}
	}
}

// TestRSAlgorithmPinning verifies that each RSA decoder accepts only its own
// algorithm. One key pair signs and verifies every case, so a cross-algorithm
// token would otherwise verify.
func TestRSAlgorithmPinning(t *testing.T) {
	privateKeyPath, publicKeyPath := generateRSAKeyPair(t)

	encoders := map[string]cryptojwt.Encoder{
		"RS256": cryptojwt.NewRS256Encoder(privateKeyPath),
		"RS384": cryptojwt.NewRS384Encoder(privateKeyPath),
		"RS512": cryptojwt.NewRS512Encoder(privateKeyPath),
	}
	publicDecoders := map[string]cryptojwt.Decoder{
		"RS256": cryptojwt.NewRS256DecoderWithPublicKeyFile(publicKeyPath),
		"RS384": cryptojwt.NewRS384DecoderWithPublicKeyFile(publicKeyPath),
		"RS512": cryptojwt.NewRS512DecoderWithPublicKeyFile(publicKeyPath),
	}
	privateDecoders := map[string]cryptojwt.Decoder{
		"RS256": cryptojwt.NewRS256DecoderWithPrivateKeyFile(privateKeyPath),
		"RS384": cryptojwt.NewRS384DecoderWithPrivateKeyFile(privateKeyPath),
		"RS512": cryptojwt.NewRS512DecoderWithPrivateKeyFile(privateKeyPath),
	}

	for _, tokenAlg := range []string{"RS256", "RS384", "RS512"} {
		token, err := encoders[tokenAlg].Encode(pinningPayload)
		if err != nil {
			t.Fatalf("Failed to encode %s token: %v", tokenAlg, err)
		}
		for _, decoderAlg := range []string{"RS256", "RS384", "RS512"} {
			for keySource, decoders := range map[string]map[string]cryptojwt.Decoder{
				"public key":  publicDecoders,
				"private key": privateDecoders,
			} {
				t.Run(tokenAlg+" token to "+decoderAlg+" decoder with "+keySource, func(t *testing.T) {
					decoded, err := decoders[decoderAlg].Decode(token)
					if tokenAlg == decoderAlg {
						assertDecodes(t, decoded, err)
						return
					}
					assertAlgRejected(t, err, tokenAlg)
				})
			}
		}
	}
}

// TestESAlgorithmPinning verifies that each ECDSA decoder accepts only its own
// algorithm. Each ECDSA algorithm is bound to a curve, so the decoder under test
// is given the very key pair that signed the token: the algorithm pin is then the
// only reason a cross-algorithm token can be rejected.
func TestESAlgorithmPinning(t *testing.T) {
	curves := map[string]elliptic.Curve{
		"ES256": elliptic.P256(),
		"ES384": elliptic.P384(),
		"ES512": elliptic.P521(),
	}
	newEncoder := map[string]func(string) cryptojwt.Encoder{
		"ES256": cryptojwt.NewES256Encoder,
		"ES384": cryptojwt.NewES384Encoder,
		"ES512": cryptojwt.NewES512Encoder,
	}
	newPublicDecoder := map[string]func(string) cryptojwt.Decoder{
		"ES256": cryptojwt.NewES256DecoderWithPublicKeyFile,
		"ES384": cryptojwt.NewES384DecoderWithPublicKeyFile,
		"ES512": cryptojwt.NewES512DecoderWithPublicKeyFile,
	}
	newPrivateDecoder := map[string]func(string) cryptojwt.Decoder{
		"ES256": cryptojwt.NewES256DecoderWithPrivateKeyFile,
		"ES384": cryptojwt.NewES384DecoderWithPrivateKeyFile,
		"ES512": cryptojwt.NewES512DecoderWithPrivateKeyFile,
	}

	algs := []string{"ES256", "ES384", "ES512"}
	for _, tokenAlg := range algs {
		privateKeyPath, publicKeyPath := generateECDSAKeyPair(t, curves[tokenAlg])
		token, err := newEncoder[tokenAlg](privateKeyPath).Encode(pinningPayload)
		if err != nil {
			t.Fatalf("Failed to encode %s token: %v", tokenAlg, err)
		}
		for _, decoderAlg := range algs {
			t.Run(tokenAlg+" token to "+decoderAlg+" decoder with public key", func(t *testing.T) {
				decoded, err := newPublicDecoder[decoderAlg](publicKeyPath).Decode(token)
				if tokenAlg == decoderAlg {
					assertDecodes(t, decoded, err)
					return
				}
				assertAlgRejected(t, err, tokenAlg)
			})
			t.Run(tokenAlg+" token to "+decoderAlg+" decoder with private key", func(t *testing.T) {
				decoded, err := newPrivateDecoder[decoderAlg](privateKeyPath).Decode(token)
				if tokenAlg == decoderAlg {
					assertDecodes(t, decoded, err)
					return
				}
				assertAlgRejected(t, err, tokenAlg)
			})
		}
	}
}

// TestCrossFamilyAlgorithmPinning verifies that a token from one algorithm family
// is rejected by a decoder from another family, and that the rejection now comes
// from the algorithm pin rather than from a key type assertion deeper in the parser.
func TestCrossFamilyAlgorithmPinning(t *testing.T) {
	secret := []byte("this-is-a-shared-secret-for-all-algorithms-hs512-requirements!!!")
	rsaPrivateKeyPath, rsaPublicKeyPath := generateRSAKeyPair(t)
	ecPrivateKeyPath, ecPublicKeyPath := generateECDSAKeyPair(t, elliptic.P256())

	hsToken, err := cryptojwt.NewHS256Encoder(secret).Encode(pinningPayload)
	if err != nil {
		t.Fatalf("Failed to encode HS256 token: %v", err)
	}
	rsToken, err := cryptojwt.NewRS256Encoder(rsaPrivateKeyPath).Encode(pinningPayload)
	if err != nil {
		t.Fatalf("Failed to encode RS256 token: %v", err)
	}
	esToken, err := cryptojwt.NewES256Encoder(ecPrivateKeyPath).Encode(pinningPayload)
	if err != nil {
		t.Fatalf("Failed to encode ES256 token: %v", err)
	}

	tests := []struct {
		name     string
		token    string
		tokenAlg string
		decoder  cryptojwt.Decoder
	}{
		{
			name:     "HS256 token to RS256 decoder",
			token:    hsToken,
			tokenAlg: "HS256",
			decoder:  cryptojwt.NewRS256DecoderWithPublicKeyFile(rsaPublicKeyPath),
		},
		{
			name:     "HS256 token to ES256 decoder",
			token:    hsToken,
			tokenAlg: "HS256",
			decoder:  cryptojwt.NewES256DecoderWithPublicKeyFile(ecPublicKeyPath),
		},
		{
			name:     "RS256 token to HS256 decoder",
			token:    rsToken,
			tokenAlg: "RS256",
			decoder:  cryptojwt.NewHS256Decoder(secret),
		},
		{
			name:     "RS256 token to ES256 decoder",
			token:    rsToken,
			tokenAlg: "RS256",
			decoder:  cryptojwt.NewES256DecoderWithPublicKeyFile(ecPublicKeyPath),
		},
		{
			name:     "ES256 token to HS256 decoder",
			token:    esToken,
			tokenAlg: "ES256",
			decoder:  cryptojwt.NewHS256Decoder(secret),
		},
		{
			name:     "ES256 token to RS256 decoder",
			token:    esToken,
			tokenAlg: "ES256",
			decoder:  cryptojwt.NewRS256DecoderWithPublicKeyFile(rsaPublicKeyPath),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.decoder.Decode(tt.token)
			assertAlgRejected(t, err, tt.tokenAlg)
		})
	}
}

// TestAlgorithmPinningWithClaimsValidation verifies the pin applies on the
// claims-validating parser branch too, not only the default one.
func TestAlgorithmPinningWithClaimsValidation(t *testing.T) {
	secret := []byte("this-is-a-shared-secret-for-all-algorithms-hs512-requirements!!!")
	opts := cryptojwt.ValidationOptions{ValidateClaims: true}

	token, err := cryptojwt.NewHS384Encoder(secret).Encode(pinningPayload)
	if err != nil {
		t.Fatalf("Failed to encode HS384 token: %v", err)
	}

	_, err = cryptojwt.NewHS256DecoderWithValidation(secret, false, opts).Decode(token)
	assertAlgRejected(t, err, "HS384")

	decoded, err := cryptojwt.NewHS384DecoderWithValidation(secret, false, opts).Decode(token)
	assertDecodes(t, decoded, err)
}
