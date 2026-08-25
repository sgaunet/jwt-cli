package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// pasetoKeyPair returns a key pair file path pair appropriate to the version.
func pasetoKeyPair(t *testing.T, version string) (string, string) {
	t.Helper()
	if version == pasetoV3 {
		return generateP384KeyPair(t)
	}
	return generateEd25519KeyPair(t)
}

// encodePasetoPublic signs a token with a fresh command instance.
func encodePasetoPublic(t *testing.T, version, privateKey string) string {
	t.Helper()
	cmd := createPasetoEncodePublicCommand()
	registerPasetoEncodeFlags(cmd)
	out, err := executeCommand(cmd,
		"--version", version,
		"--private-key", privateKey,
		"--payload", validPayload,
	)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}
	return strings.TrimSpace(out)
}

func TestPasetoPublicCommand_RoundTrip(t *testing.T) {
	// v3 exercises the NIST P-384 path, which was entirely non-functional
	// before the PEM loaders were added.
	tests := []struct {
		name    string
		version string
		prefix  string
	}{
		{"v4 public round trip", "v4", "v4.public."},
		{"v3 public round trip", "v3", "v3.public."},
		{"v2 public round trip", "v2", "v2.public."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, publicKey := pasetoKeyPair(t, tt.version)
			token := encodePasetoPublic(t, tt.version, privateKey)
			if !strings.HasPrefix(token, tt.prefix) {
				t.Fatalf("Expected token to start with %q, got: %s", tt.prefix, token)
			}

			t.Run("decode with public key", func(t *testing.T) {
				cmd := createPasetoDecodePublicCommand()
				registerPasetoDecodeFlags(cmd)
				out, err := executeCommand(cmd,
					"--version", tt.version,
					"--public-key", publicKey,
					"--token", token,
				)
				if err != nil {
					t.Fatalf("Expected no error, got: %v", err)
				}
				if !strings.Contains(out, "John Doe") {
					t.Errorf("Expected claims to contain 'John Doe', got: %s", out)
				}
			})

			t.Run("decode with private key", func(t *testing.T) {
				cmd := createPasetoDecodePublicCommand()
				registerPasetoDecodeFlags(cmd)
				out, err := executeCommand(cmd,
					"--version", tt.version,
					"--private-key", privateKey,
					"--token", token,
				)
				if err != nil {
					t.Fatalf("Expected no error, got: %v", err)
				}
				if !strings.Contains(out, "John Doe") {
					t.Errorf("Expected claims to contain 'John Doe', got: %s", out)
				}
			})
		})
	}
}

func TestPasetoDecodePublicCommand_PublicKeyPrecedence(t *testing.T) {
	// When both keys are supplied the public key wins, matching decode-rs.
	privateKey, publicKey := generateEd25519KeyPair(t)
	token := encodePasetoPublic(t, pasetoV4, privateKey)

	cmd := createPasetoDecodePublicCommand()
	registerPasetoDecodeFlags(cmd)
	out, err := executeCommand(cmd,
		"--public-key", publicKey,
		"--private-key", privateKey,
		"--token", token,
	)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !strings.Contains(out, "John Doe") {
		t.Errorf("Expected claims to contain 'John Doe', got: %s", out)
	}
}

func TestPasetoEncodePublicCommand_MissingPrivateKey(t *testing.T) {
	cmd := createPasetoEncodePublicCommand()
	registerPasetoEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--payload", validPayload)
	if err == nil {
		t.Fatal("Expected error for missing private key, got nil")
	}
	if !strings.Contains(err.Error(), "private key file is required") {
		t.Errorf("Expected private key required error, got: %v", err)
	}
}

func TestPasetoDecodePublicCommand_MissingKeys(t *testing.T) {
	cmd := createPasetoDecodePublicCommand()
	registerPasetoDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--token", "v4.public.abc")
	if err == nil {
		t.Fatal("Expected error for missing keys, got nil")
	}
	if !strings.Contains(err.Error(), "key file is required") {
		t.Errorf("Expected key required error, got: %v", err)
	}
}

func TestPasetoPublicCommand_NonExistentKeyFile(t *testing.T) {
	cmd := createPasetoEncodePublicCommand()
	registerPasetoEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--private-key", getNonExistentPath(t),
		"--payload", validPayload,
	)
	if err == nil {
		t.Fatal("Expected error for non-existent key file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read private key file") {
		t.Errorf("Expected file read error, got: %v", err)
	}
}

func TestPasetoPublicCommand_InvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		keyFile func(*testing.T) string
	}{
		{"malformed PEM", createInvalidPEMFile},
		{"wrong PEM block type", func(t *testing.T) string {
			t.Helper()
			return createWrongTypePEMFile(t, "CERTIFICATE")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := createPasetoEncodePublicCommand()
			registerPasetoEncodeFlags(cmd)

			_, err := executeCommand(cmd,
				"--private-key", tt.keyFile(t),
				"--payload", validPayload,
			)
			if err == nil {
				t.Fatal("Expected error for invalid key file, got nil")
			}
			if !strings.Contains(err.Error(), "invalid key") {
				t.Errorf("Expected invalid key error, got: %v", err)
			}
		})
	}
}

func TestPasetoPublicCommand_WrongCurveForV3(t *testing.T) {
	// A v3 command handed an Ed25519 key must say so rather than fail obscurely.
	privateKey, _ := generateEd25519KeyPair(t)

	cmd := createPasetoEncodePublicCommand()
	registerPasetoEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--version", pasetoV3,
		"--private-key", privateKey,
		"--payload", validPayload,
	)
	if err == nil {
		t.Fatal("Expected error for an Ed25519 key on v3, got nil")
	}
	if !strings.Contains(err.Error(), "not ECDSA") {
		t.Errorf("Expected not-ECDSA error, got: %v", err)
	}
}

func TestPasetoDecodePublicCommand_WrongKey(t *testing.T) {
	privateKey, _ := generateEd25519KeyPair(t)
	_, otherPublicKey := generateEd25519KeyPair(t)
	token := encodePasetoPublic(t, pasetoV4, privateKey)

	cmd := createPasetoDecodePublicCommand()
	registerPasetoDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--public-key", otherPublicKey, "--token", token)
	if err == nil {
		t.Fatal("Expected error when decoding with the wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "decoding failed") {
		t.Errorf("Expected decoding failure, got: %v", err)
	}
}

func TestPasetoPublicCommand_DeprecatedFlags(t *testing.T) {
	privateKey, publicKey := generateEd25519KeyPair(t)

	encodeCmd := createPasetoEncodePublicCommand()
	registerPasetoEncodeFlags(encodeCmd)
	out, err := executeCommand(encodeCmd, "--pk", privateKey, "--p", validPayload)
	if err != nil {
		t.Fatalf("Expected deprecated --pk/--p to work, got: %v", err)
	}
	token := extractToken(t, out, "v4.public.")

	tests := []struct {
		name string
		args []string
	}{
		{"deprecated --pubk", []string{"--t", token, "--pubk", publicKey}},
		{"deprecated --pk", []string{"--t", token, "--pk", privateKey}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := createPasetoDecodePublicCommand()
			registerPasetoDecodeFlags(cmd)
			if _, err := executeCommand(cmd, tt.args...); err != nil {
				t.Fatalf("Expected deprecated flags to work, got: %v", err)
			}
		})
	}
}

func TestPasetoGenkeysCommands(t *testing.T) {
	// The printed recipes are the documented way to create keys, so at minimum
	// they must name the right algorithm and output files.
	tests := []struct {
		name     string
		cmd      *cobra.Command
		contains []string
	}{
		{"v4 genkeys", createPasetoGenkeysCommand(pasetoV4, "Ed25519", ed25519GenkeysLong(pasetoV4), ed25519GenkeysRecipe(pasetoV4)),
			[]string{"Ed25519", "paseto-v4-private.pem", "paseto-v4-public.pem"}},
		{"v3 genkeys", createPasetoGenkeysCommand(pasetoV3, "P-384", "long", []string{"openssl ecparam -genkey -name secp384r1 -noout -out paseto-v3-private.pem", "openssl ec -in paseto-v3-private.pem -pubout -out paseto-v3-public.pem"}),
			[]string{"secp384r1", "paseto-v3-private.pem", "paseto-v3-public.pem"}},
		{"v2 genkeys", createPasetoGenkeysCommand(pasetoV2, "Ed25519", ed25519GenkeysLong(pasetoV2), ed25519GenkeysRecipe(pasetoV2)),
			[]string{"Ed25519", "paseto-v2-private.pem", "paseto-v2-public.pem"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := executeCommand(tt.cmd)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			for _, want := range tt.contains {
				if !strings.Contains(out, want) {
					t.Errorf("Expected output to contain %q, got: %s", want, out)
				}
			}
			// The removed DER recipe produced a key the tool rejects.
			if strings.Contains(out, "-outform DER") {
				t.Error("genkeys must not print the DER recipe, which yields an unusable key")
			}
		})
	}
}

func TestPasetoDecodePublicCommand_ValidateClaims(t *testing.T) {
	for _, version := range []string{"v4", "v3", "v2"} {
		t.Run(version, func(t *testing.T) {
			privateKey, publicKey := pasetoKeyPair(t, version)

			encode := createPasetoEncodePublicCommand()
			registerPasetoEncodeFlags(encode)
			out, err := executeCommand(encode,
				"--version", version,
				"--private-key", privateKey,
				"--payload", expiredPasetoPayload(time.Hour),
			)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}
			token := strings.TrimSpace(out)

			cmd := createPasetoDecodePublicCommand()
			registerPasetoDecodeFlags(cmd)
			stderr := captureStderr(t, func() {
				_, err = executeCommand(cmd,
					"--version", version,
					"--public-key", publicKey,
					"--token", token,
					"--validate-claims",
				)
			})
			if err == nil {
				t.Fatal("Expected an error for an expired token, got nil")
			}
			if !strings.Contains(stderr, "token has expired") {
				t.Errorf("Expected the expiry to be reported, got: %s", stderr)
			}

			cmd = createPasetoDecodePublicCommand()
			registerPasetoDecodeFlags(cmd)
			out, err = executeCommand(cmd,
				"--version", version,
				"--public-key", publicKey,
				"--token", token,
				"--validate-claims",
				"--clock-skew", "24h",
			)
			if err != nil {
				t.Fatalf("Expected the token to decode inside the tolerance, got: %v", err)
			}
			if !strings.Contains(out, "John Doe") {
				t.Errorf("Expected claims in output, got: %s", out)
			}
		})
	}
}
