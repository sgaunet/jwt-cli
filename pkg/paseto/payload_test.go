package paseto_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

// TestNonObjectPayloadIsRejected pins that only a JSON object is accepted as a
// payload. "null" is the interesting case: it unmarshals into a nil map without
// error, so it slipped through until parsePayload gained its own nil check.
func TestNonObjectPayloadIsRejected(t *testing.T) {
	key := newLocalKey(t)

	tests := []struct {
		name    string
		payload string
	}{
		{"null literal", `null`},
		{"array", `[1,2,3]`},
		{"string", `"claims"`},
		{"number", `123`},
		{"malformed", `{bad`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := paseto.NewLocalV4Encoder(key)
			if err != nil {
				t.Fatalf("Failed to build encoder: %v", err)
			}

			token, err := enc.Encode(tt.payload)
			if err == nil {
				t.Fatalf("Expected %s to be rejected, got token: %s", tt.name, token)
			}
			if !errors.Is(err, paseto.ErrInvalidPayload) {
				t.Errorf("Expected errors.Is(err, ErrInvalidPayload), got: %v", err)
			}
		})
	}
}

// TestObjectPayloadIsAccepted is the counterpart: an empty object is a valid
// claim set, so the nil-map guard must not reject it.
func TestObjectPayloadIsAccepted(t *testing.T) {
	key := newLocalKey(t)

	enc, err := paseto.NewLocalV4Encoder(key)
	if err != nil {
		t.Fatalf("Failed to build encoder: %v", err)
	}

	token, err := enc.Encode(`{}`)
	if err != nil {
		t.Fatalf("Expected an empty JSON object to be accepted, got: %v", err)
	}
	if !strings.HasPrefix(token, "v4.local.") {
		t.Errorf("Expected a v4 local token, got: %s", token)
	}
}
