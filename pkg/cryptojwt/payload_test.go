package cryptojwt_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// payloadTestSecret is long enough for HS256's RFC 7518 minimum.
const payloadTestSecret = "0123456789abcdef0123456789abcdef"

// TestNonObjectPayloadIsRejected pins that only a JSON object can become a
// claims set, as RFC 7519 section 4 requires.
//
// The literal "null" is the case that mattered: encoding/json unmarshals it into
// a nil map without reporting an error, so it slipped past the type check every
// other non-object payload hit, and jwt-cli signed a token whose payload segment
// was the four bytes "null". pkg/paseto already guarded against this; the JWT
// path did not.
func TestNonObjectPayloadIsRejected(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"null literal", "null"},
		{"array", "[1,2,3]"},
		{"string", `"claims"`},
		{"number", "123"},
		{"boolean", "true"},
		{"malformed", "{bad"},
		{"empty", ""},
	}

	encoder := cryptojwt.NewHS256EncoderWithOptions([]byte(payloadTestSecret), false)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			token, err := encoder.Encode(tt.payload)
			if err == nil {
				t.Fatalf("payload %q should be rejected, got token %q", tt.payload, token)
			}
			if !errors.Is(err, cryptojwt.ErrInvalidPayload) {
				t.Errorf("payload %q should report ErrInvalidPayload, got: %v", tt.payload, err)
			}
		})
	}
}

// TestObjectPayloadIsAccepted keeps the boundary honest: the guard added for
// "null" must not reject a legitimately empty object.
func TestObjectPayloadIsAccepted(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"empty object", "{}"},
		{"object with claims", `{"sub":"alice"}`},
		{"object with a null member", `{"sub":null}`},
	}

	encoder := cryptojwt.NewHS256EncoderWithOptions([]byte(payloadTestSecret), false)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			token, err := encoder.Encode(tt.payload)
			if err != nil {
				t.Fatalf("payload %q should be accepted, got: %v", tt.payload, err)
			}

			// The payload segment must decode to a JSON object, not a bare
			// literal - that is the property the guard exists to keep.
			segments := strings.Split(token, ".")
			if len(segments) != 3 {
				t.Fatalf("expected three token segments, got %d", len(segments))
			}
			decoded, err := base64.RawURLEncoding.DecodeString(segments[1])
			if err != nil {
				t.Fatalf("payload segment should be base64url: %v", err)
			}
			if !strings.HasPrefix(string(decoded), "{") {
				t.Errorf("payload segment should be a JSON object, got %q", decoded)
			}
		})
	}
}
