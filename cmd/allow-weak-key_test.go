package cmd

import (
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// rsCommandConstructors bundles the constructors the RS* commands are wired to,
// so the --allow-weak-key tests cover the same code path as the real CLI.
type rsCommandConstructors struct {
	name           string
	algorithm      string
	encoder        asymmetricEncoderFunc
	pubKeyDecoder  asymmetricDecoderFunc
	privKeyDecoder asymmetricDecoderFunc
}

func rsCommandTable() []rsCommandConstructors {
	return []rsCommandConstructors{
		{
			name:           "RS256",
			algorithm:      "rs256",
			encoder:        cryptojwt.NewRS256EncoderWithOptions,
			pubKeyDecoder:  cryptojwt.NewRS256DecoderWithPublicKeyFileAndOptions,
			privKeyDecoder: cryptojwt.NewRS256DecoderWithPrivateKeyFileAndOptions,
		},
		{
			name:           "RS384",
			algorithm:      "rs384",
			encoder:        cryptojwt.NewRS384EncoderWithOptions,
			pubKeyDecoder:  cryptojwt.NewRS384DecoderWithPublicKeyFileAndOptions,
			privKeyDecoder: cryptojwt.NewRS384DecoderWithPrivateKeyFileAndOptions,
		},
		{
			name:           "RS512",
			algorithm:      "rs512",
			encoder:        cryptojwt.NewRS512EncoderWithOptions,
			pubKeyDecoder:  cryptojwt.NewRS512DecoderWithPublicKeyFileAndOptions,
			privKeyDecoder: cryptojwt.NewRS512DecoderWithPrivateKeyFileAndOptions,
		},
	}
}

// TestRSEncodeCommand_WeakKeyRejected checks the encode commands refuse a
// below-minimum RSA key unless --allow-weak-key is passed.
func TestRSEncodeCommand_WeakKeyRejected(t *testing.T) {
	for _, tt := range rsCommandTable() {
		t.Run(tt.name+"_without_flag", func(t *testing.T) {
			privateKey, _ := generateRSAKeyPairWithBits(t, testWeakRSAKeySize)

			cmd := createAsymmetricEncodeCommand(rsKeyVocab, tt.algorithm, "Test", "Test", "Test", tt.encoder)

			_, err := executeCommand(cmd, "--payload", validPayload, "--private-key", privateKey)
			if err == nil {
				t.Fatal("Expected error for a 1024-bit RSA key, got nil")
			}
			if !strings.Contains(err.Error(), "1024 bits") {
				t.Errorf("Expected the error to name the key size, got: %v", err)
			}
		})

		t.Run(tt.name+"_with_flag", func(t *testing.T) {
			privateKey, _ := generateRSAKeyPairWithBits(t, testWeakRSAKeySize)

			cmd := createAsymmetricEncodeCommand(rsKeyVocab, tt.algorithm, "Test", "Test", "Test", tt.encoder)

			output, err := executeCommand(cmd,
				"--payload", validPayload,
				"--private-key", privateKey,
				"--allow-weak-key",
			)
			if err != nil {
				t.Fatalf("Expected no error with --allow-weak-key, got: %v", err)
			}
			if strings.TrimSpace(output) == "" {
				t.Error("Expected token output with --allow-weak-key")
			}
		})
	}
}

// TestRSDecodeCommand_WeakKeyRejected checks both decode key paths enforce the
// same floor, and that --allow-weak-key lifts it for each.
func TestRSDecodeCommand_WeakKeyRejected(t *testing.T) {
	for _, tt := range rsCommandTable() {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, publicKey := generateRSAKeyPairWithBits(t, testWeakRSAKeySize)

			encCmd := createAsymmetricEncodeCommand(rsKeyVocab, tt.algorithm, "Test", "Test", "Test", tt.encoder)
			tokenOutput, err := executeCommand(encCmd,
				"--payload", validPayload,
				"--private-key", privateKey,
				"--allow-weak-key",
			)
			if err != nil {
				t.Fatalf("Failed to prepare a token signed with a weak key: %v", err)
			}
			token := strings.TrimSpace(tokenOutput)

			for _, keyFlag := range []struct{ flag, path string }{
				{"--public-key", publicKey},
				{"--private-key", privateKey},
			} {
				decCmd := createAsymmetricDecodeCommand(
					rsKeyVocab, tt.algorithm, "Test", "Test", "Test", tt.pubKeyDecoder, tt.privKeyDecoder)
				if _, err := executeCommand(decCmd, "--token", token, keyFlag.flag, keyFlag.path); err == nil {
					t.Errorf("Expected %s decode to reject a 1024-bit key", keyFlag.flag)
				}

				decCmd = createAsymmetricDecodeCommand(
					rsKeyVocab, tt.algorithm, "Test", "Test", "Test", tt.pubKeyDecoder, tt.privKeyDecoder)
				output, err := executeCommand(decCmd,
					"--token", token, keyFlag.flag, keyFlag.path, "--allow-weak-key")
				if err != nil {
					t.Errorf("Expected %s decode to succeed with --allow-weak-key, got: %v", keyFlag.flag, err)
				}
				if !strings.Contains(output, "1234567890") {
					t.Errorf("Expected claims to round-trip via %s, got: %s", keyFlag.flag, output)
				}
			}
		})
	}
}

// TestESCommands_RejectAllowWeakKey pins that --allow-weak-key does not exist on
// the ECDSA commands. An ECDSA key size is fixed by the curve the algorithm
// names, so there is nothing for the flag to override; it used to be accepted
// and silently ignored, which told an operator their opt-out had taken effect.
func TestESCommands_RejectAllowWeakKey(t *testing.T) {
	privateKey, publicKey := generateECDSAKeyPair(t, elliptic.P256())

	encCmd := createAsymmetricEncodeCommand(
		esKeyVocab, "es256", "Test", "Test", "Test", ignoreWeakKeyEncoder(cryptojwt.NewES256Encoder))
	_, err := executeCommand(encCmd,
		"--payload", validPayload, "--private-key", privateKey, "--allow-weak-key")
	if err == nil {
		t.Fatal("Expected ES256 encode to reject --allow-weak-key, got no error")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("Expected an unknown-flag error, got: %v", err)
	}

	decCmd := createAsymmetricDecodeCommand(esKeyVocab, "es256", "Test", "Test", "Test",
		ignoreWeakKeyDecoder(cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation),
		ignoreWeakKeyDecoder(cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation))
	_, err = executeCommand(decCmd,
		"--token", "irrelevant", "--public-key", publicKey, "--allow-weak-key")
	if err == nil {
		t.Fatal("Expected ES256 decode to reject --allow-weak-key, got no error")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("Expected an unknown-flag error, got: %v", err)
	}
}

// TestESCommands_RoundTripWithoutWeakKeyFlag keeps the ECDSA happy path covered
// now that TestESCommands_RejectAllowWeakKey no longer exercises it.
func TestESCommands_RoundTripWithoutWeakKeyFlag(t *testing.T) {
	privateKey, publicKey := generateECDSAKeyPair(t, elliptic.P256())

	encCmd := createAsymmetricEncodeCommand(
		esKeyVocab, "es256", "Test", "Test", "Test", ignoreWeakKeyEncoder(cryptojwt.NewES256Encoder))
	tokenOutput, err := executeCommand(encCmd, "--payload", validPayload, "--private-key", privateKey)
	if err != nil {
		t.Fatalf("Expected ES256 encode to succeed, got: %v", err)
	}

	decCmd := createAsymmetricDecodeCommand(esKeyVocab, "es256", "Test", "Test", "Test",
		ignoreWeakKeyDecoder(cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation),
		ignoreWeakKeyDecoder(cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation))
	output, err := executeCommand(decCmd,
		"--token", strings.TrimSpace(tokenOutput), "--public-key", publicKey)
	if err != nil {
		t.Fatalf("Expected ES256 decode to succeed, got: %v", err)
	}
	if !strings.Contains(output, "1234567890") {
		t.Errorf("Expected claims to round-trip, got: %s", output)
	}
}
