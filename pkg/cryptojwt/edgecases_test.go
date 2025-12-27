package cryptojwt_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestMalformedTokens tests various malformed JWT token scenarios
func TestMalformedTokens(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	decoder := cryptojwt.NewHS256DecoderWithOptions(secret, true)

	tests := []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "incomplete token - only header",
			token:   "eyJhbGci",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "wrong parts count - only two parts",
			token:   "one.two",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "wrong parts count - four parts",
			token:   "one.two.three.four",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "invalid base64 characters",
			token:   "invalid!@#.invalid!@#.invalid!@#",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "valid structure but invalid signature",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalidSignatureHere",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "token with only dots",
			token:   "...",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "token with whitespace",
			token:   "header.payload.signature ",
			wantErr: true,
			errMsg:  "token",
		},
		{
			name:    "token with newlines",
			token:   "header.payload.\nsignature",
			wantErr: true,
			errMsg:  "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decoder.Decode(tt.token)
			if tt.wantErr && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.name, err)
			}
			if err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
			}
		})
	}
}

// TestSpecialCharactersInSecrets tests secrets with various special characters
func TestSpecialCharactersInSecrets(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
	}{
		{
			name:   "secret with spaces",
			secret: []byte("secret with spaces and 32 bytes!"),
		},
		{
			name:   "secret with newlines",
			secret: []byte("secret\nwith\nnewlines\nand32bytes!"),
		},
		{
			name:   "secret with tabs",
			secret: []byte("secret\twith\ttabs\tand\t32\tbytes!"),
		},
		{
			name:   "secret with unicode",
			secret: []byte("секретный-ключ-with-32-bytes!!"),
		},
		{
			name:   "secret with emoji",
			secret: []byte("🔐🔑secret-key-with-32-bytes!🔐"),
		},
		{
			name:   "secret with null bytes",
			secret: []byte("secret\x00with\x00null\x00and32bytes"),
		},
		{
			name:   "secret with control characters",
			secret: []byte("secret\r\nwith\x01control\x02chars!"),
		},
		{
			name:   "secret with special symbols",
			secret: []byte("!@#$%^&*()_+-=[]{}|;':\",./<>?"),
		},
		{
			name:   "secret with mixed case",
			secret: []byte("MiXeD-CaSe-SeCrEt-WiTh-32-Bytes"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := cryptojwt.NewHS256EncoderWithOptions(tt.secret, true)
			decoder := cryptojwt.NewHS256DecoderWithOptions(tt.secret, true)

			token, err := encoder.Encode(validPayload)
			if err != nil {
				t.Fatalf("Failed to encode with special secret: %v", err)
			}

			decoded, err := decoder.Decode(token)
			if err != nil {
				t.Fatalf("Failed to decode with special secret: %v", err)
			}

			if !strings.Contains(decoded, "John Doe") {
				t.Errorf("Expected decoded payload to contain 'John Doe', got: %s", decoded)
			}
		})
	}
}

// TestBoundaryConditions tests various boundary conditions for payloads
func TestBoundaryConditions(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	encoder := cryptojwt.NewHS256Encoder(secret)
	decoder := cryptojwt.NewHS256Decoder(secret)

	tests := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{
			name:    "empty object",
			payload: "{}",
			wantErr: false,
		},
		{
			name:    "null values",
			payload: `{"key":null,"name":"test","value":null}`,
			wantErr: false,
		},
		{
			name:    "deep nesting",
			payload: `{"l1":{"l2":{"l3":{"l4":{"l5":{"l6":{"l7":{"l8":{"l9":{"l10":"deep"}}}}}}}}}}`,
			wantErr: false,
		},
		{
			name:    "array payload - not supported by JWT MapClaims",
			payload: `[1,2,3,4,5]`,
			wantErr: true,
		},
		{
			name:    "array of objects - not supported by JWT MapClaims",
			payload: `[{"id":1},{"id":2},{"id":3}]`,
			wantErr: true,
		},
		{
			name:    "boolean values",
			payload: `{"true":true,"false":false}`,
			wantErr: false,
		},
		{
			name:    "numeric values",
			payload: `{"int":42,"float":3.14,"negative":-100,"zero":0}`,
			wantErr: false,
		},
		{
			name:    "empty string values",
			payload: `{"key":"","another":""}`,
			wantErr: false,
		},
		{
			name:    "unicode in payload",
			payload: `{"message":"Hello 世界","emoji":"🎉"}`,
			wantErr: false,
		},
		{
			name:    "special characters in payload",
			payload: `{"text":"Line1\nLine2\tTabbed"}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := encoder.Encode(tt.payload)
			if tt.wantErr && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.name, err)
				return
			}
			if err != nil {
				return
			}

			decoded, err := decoder.Decode(token)
			if err != nil {
				t.Errorf("Failed to decode %s: %v", tt.name, err)
				return
			}

			if decoded == "" {
				t.Errorf("Expected non-empty decoded payload for %s", tt.name)
			}
		})
	}
}

// TestLargePayloads tests encoding and decoding of large payloads
func TestLargePayloads(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	encoder := cryptojwt.NewHS256Encoder(secret)
	decoder := cryptojwt.NewHS256Decoder(secret)

	tests := []struct {
		name        string
		payloadSize int
	}{
		{
			name:        "1KB payload",
			payloadSize: 1024,
		},
		{
			name:        "10KB payload",
			payloadSize: 10 * 1024,
		},
		{
			name:        "100KB payload",
			payloadSize: 100 * 1024,
		},
		{
			name:        "1MB payload",
			payloadSize: 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create large payload
			largeData := strings.Repeat("x", tt.payloadSize)
			payload := fmt.Sprintf(`{"data":"%s"}`, largeData)

			token, err := encoder.Encode(payload)
			if err != nil {
				t.Fatalf("Failed to encode large payload: %v", err)
			}

			if token == "" {
				t.Fatal("Expected non-empty token for large payload")
			}

			decoded, err := decoder.Decode(token)
			if err != nil {
				t.Fatalf("Failed to decode large payload: %v", err)
			}

			if !strings.Contains(decoded, largeData) {
				t.Error("Decoded payload does not contain expected large data")
			}
		})
	}
}

// TestTokenExpiration tests token expiration scenarios with claims validation
func TestTokenExpiration(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")

	now := time.Now().Unix()
	tests := []struct {
		name        string
		payload     string
		validate    bool
		expectError bool
	}{
		{
			name:        "expired token with validation",
			payload:     fmt.Sprintf(`{"user":"test","exp":%d}`, now-3600),
			validate:    true,
			expectError: true,
		},
		{
			name:        "expired token without validation",
			payload:     fmt.Sprintf(`{"user":"test","exp":%d}`, now-3600),
			validate:    false,
			expectError: false,
		},
		{
			name:        "valid future exp with validation",
			payload:     fmt.Sprintf(`{"user":"test","exp":%d}`, now+3600),
			validate:    true,
			expectError: false,
		},
		{
			name:        "token with no exp claim",
			payload:     `{"user":"test"}`,
			validate:    true,
			expectError: false,
		},
		{
			name:        "token with nbf in future",
			payload:     fmt.Sprintf(`{"user":"test","nbf":%d}`, now+3600),
			validate:    true,
			expectError: true,
		},
		{
			name:        "token with valid nbf",
			payload:     fmt.Sprintf(`{"user":"test","nbf":%d}`, now-3600),
			validate:    true,
			expectError: false,
		},
		{
			name:        "token expiring soon (1 second)",
			payload:     fmt.Sprintf(`{"user":"test","exp":%d}`, now+1),
			validate:    true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validationOpts := cryptojwt.ValidationOptions{
				ValidateClaims: tt.validate,
				ClockSkew:      0,
			}

			encoder := cryptojwt.NewHS256EncoderWithValidation(secret, true, cryptojwt.ValidationOptions{})
			decoder := cryptojwt.NewHS256DecoderWithValidation(secret, true, validationOpts)

			token, err := encoder.Encode(tt.payload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			_, err = decoder.Decode(token)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestClockSkewTolerance tests clock skew tolerance in validation
func TestClockSkewTolerance(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	now := time.Now().Unix()

	tests := []struct {
		name        string
		exp         int64
		clockSkew   time.Duration
		expectError bool
	}{
		{
			name:        "expired 30s ago, no skew",
			exp:         now - 30,
			clockSkew:   0,
			expectError: true,
		},
		{
			name:        "expired 30s ago, 1min skew",
			exp:         now - 30,
			clockSkew:   1 * time.Minute,
			expectError: false,
		},
		{
			name:        "expired 2min ago, 1min skew",
			exp:         now - 120,
			clockSkew:   1 * time.Minute,
			expectError: true,
		},
		{
			name:        "valid token with skew",
			exp:         now + 3600,
			clockSkew:   5 * time.Minute,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := fmt.Sprintf(`{"user":"test","exp":%d}`, tt.exp)

			validationOpts := cryptojwt.ValidationOptions{
				ValidateClaims: true,
				ClockSkew:      tt.clockSkew,
			}

			encoder := cryptojwt.NewHS256EncoderWithValidation(secret, true, cryptojwt.ValidationOptions{})
			decoder := cryptojwt.NewHS256DecoderWithValidation(secret, true, validationOpts)

			token, err := encoder.Encode(payload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			_, err = decoder.Decode(token)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestConcurrentOperations tests concurrent encoding and decoding
func TestConcurrentOperations(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	encoder := cryptojwt.NewHS256Encoder(secret)
	decoder := cryptojwt.NewHS256Decoder(secret)

	t.Run("concurrent encoding", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 100

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				payload := fmt.Sprintf(`{"id":%d,"user":"test"}`, id)
				token, err := encoder.Encode(payload)
				if err != nil {
					t.Errorf("Concurrent encode failed for id %d: %v", id, err)
					return
				}
				if token == "" {
					t.Errorf("Empty token for id %d", id)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent decoding", func(t *testing.T) {
		// First create a valid token
		token, err := encoder.Encode(validPayload)
		if err != nil {
			t.Fatalf("Failed to create test token: %v", err)
		}

		var wg sync.WaitGroup
		iterations := 100

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				decoded, err := decoder.Decode(token)
				if err != nil {
					t.Errorf("Concurrent decode failed: %v", err)
					return
				}
				if !strings.Contains(decoded, "John Doe") {
					t.Error("Decoded payload does not contain expected content")
				}
			}()
		}

		wg.Wait()
	})

	t.Run("mixed concurrent operations", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 50

		for i := 0; i < iterations; i++ {
			wg.Add(2)
			// Concurrent encode
			go func(id int) {
				defer wg.Done()
				payload := fmt.Sprintf(`{"id":%d}`, id)
				_, err := encoder.Encode(payload)
				if err != nil {
					t.Errorf("Mixed concurrent encode failed: %v", err)
				}
			}(i)

			// Concurrent decode
			go func() {
				defer wg.Done()
				token, err := encoder.Encode(validPayload)
				if err != nil {
					return
				}
				_, err = decoder.Decode(token)
				if err != nil {
					t.Errorf("Mixed concurrent decode failed: %v", err)
				}
			}()
		}

		wg.Wait()
	})
}

// TestInvalidJSONStructures tests various invalid JSON structures
func TestInvalidJSONStructures(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	encoder := cryptojwt.NewHS256Encoder(secret)

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "unclosed brace",
			payload: `{"key":"value"`,
		},
		{
			name:    "unclosed bracket",
			payload: `["item1","item2"`,
		},
		{
			name:    "trailing comma",
			payload: `{"key":"value",}`,
		},
		{
			name:    "single quotes instead of double",
			payload: `{'key':'value'}`,
		},
		{
			name:    "unquoted keys",
			payload: `{key:"value"}`,
		},
		{
			name:    "completely invalid",
			payload: `this is not json`,
		},
		{
			name:    "just a string (not object or array)",
			payload: `"just a string"`,
		},
		{
			name:    "just a number",
			payload: `42`,
		},
		{
			name:    "just a boolean",
			payload: `true`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encoder.Encode(tt.payload)
			if err == nil {
				t.Errorf("Expected error for invalid JSON: %s", tt.name)
			}
			if !strings.Contains(err.Error(), "payload is not a valid JSON") {
				t.Errorf("Expected JSON error, got: %v", err)
			}
		})
	}
}

// TestMaximumTokenLength tests handling of very long tokens
func TestMaximumTokenLength(t *testing.T) {
	secret := []byte("test-secret-key-for-hs256-32bytes")
	encoder := cryptojwt.NewHS256Encoder(secret)
	decoder := cryptojwt.NewHS256Decoder(secret)

	// Create payload with many fields to generate a long token
	fields := make([]string, 1000)
	for i := 0; i < len(fields); i++ {
		fields[i] = fmt.Sprintf(`"field%d":"value%d"`, i, i)
	}
	payload := fmt.Sprintf(`{%s}`, strings.Join(fields, ","))

	token, err := encoder.Encode(payload)
	if err != nil {
		t.Fatalf("Failed to encode long payload: %v", err)
	}

	if len(token) < 1000 {
		t.Errorf("Expected token length > 1000, got %d", len(token))
	}

	decoded, err := decoder.Decode(token)
	if err != nil {
		t.Fatalf("Failed to decode long token: %v", err)
	}

	if !strings.Contains(decoded, "field999") {
		t.Error("Decoded payload missing expected fields")
	}
}
