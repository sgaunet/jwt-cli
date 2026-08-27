package pemkey_test

import (
	"encoding/pem"
	"errors"
	"testing"

	"github.com/sgaunet/jwt-cli/internal/pemkey"
)

// encodeBlock renders a PEM block with optional headers.
func encodeBlock(blockType string, headers map[string]string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    blockType,
		Headers: headers,
		Bytes:   []byte("not-a-real-key"),
	})
}

// TestCheck covers both ways OpenSSL marks a key as encrypted.
//
// No real encryption is needed: the check is type- and header-only, which is the
// point - it runs before any parser touches the ciphertext.
func TestCheck(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantEncrypted bool
	}{
		{
			name:          "PKCS#8 encrypted block type",
			input:         encodeBlock("ENCRYPTED PRIVATE KEY", nil),
			wantEncrypted: true,
		},
		{
			// The legacy form keeps the ordinary block type, which is why the
			// type alone cannot be relied on.
			name: "legacy Proc-Type header on an RSA key",
			input: encodeBlock("RSA PRIVATE KEY", map[string]string{
				"Proc-Type": "4,ENCRYPTED",
				"DEK-Info":  "AES-256-CBC,0123456789ABCDEF0123456789ABCDEF",
			}),
			wantEncrypted: true,
		},
		{
			name: "legacy Proc-Type header on an EC key",
			input: encodeBlock("EC PRIVATE KEY", map[string]string{
				"Proc-Type": "4,ENCRYPTED",
				"DEK-Info":  "AES-256-CBC,0123456789ABCDEF0123456789ABCDEF",
			}),
			wantEncrypted: true,
		},
		{
			name: "DEK-Info alone",
			input: encodeBlock("RSA PRIVATE KEY", map[string]string{
				"DEK-Info": "AES-256-CBC,0123456789ABCDEF0123456789ABCDEF",
			}),
			wantEncrypted: true,
		},
		{
			name:          "plain PKCS#8 key",
			input:         encodeBlock("PRIVATE KEY", nil),
			wantEncrypted: false,
		},
		{
			name:          "plain EC key",
			input:         encodeBlock("EC PRIVATE KEY", nil),
			wantEncrypted: false,
		},
		{
			name:          "public key",
			input:         encodeBlock("PUBLIC KEY", nil),
			wantEncrypted: false,
		},
		{
			name:          "certificate",
			input:         encodeBlock("CERTIFICATE", nil),
			wantEncrypted: false,
		},
		{
			// Raw key bytes are a legitimate form for PASETO, so there is
			// nothing to inspect and nothing to report.
			name:          "not PEM at all",
			input:         []byte("just some bytes"),
			wantEncrypted: false,
		},
		{
			name:          "empty input",
			input:         nil,
			wantEncrypted: false,
		},
		{
			name:          "Proc-Type present but not encrypted",
			input:         encodeBlock("RSA PRIVATE KEY", map[string]string{"Proc-Type": "4,MIC-ONLY"}),
			wantEncrypted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pemkey.Check(tt.input)

			if !tt.wantEncrypted {
				if err != nil {
					t.Errorf("Check should accept this input, got: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("Check should report an encrypted key, got nil")
			}
			if !errors.Is(err, pemkey.ErrEncrypted) {
				t.Errorf("Check should report ErrEncrypted, got: %v", err)
			}
		})
	}
}
