package paseto_test

import (
	"strings"
	"testing"

	gopaseto "aidanwoods.dev/go-paseto"
	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

// mintFooterToken builds a v4.local token carrying a footer.
//
// It goes through go-paseto directly because jwt-cli has no way to write a
// footer: the gap this covers is decoding a token minted elsewhere, which is
// where footers actually come from - PASETO's own spec uses them for key-id
// rotation metadata.
func mintFooterToken(t *testing.T, footer string) (tokenString, keyHex string) {
	t.Helper()

	key := gopaseto.NewV4SymmetricKey()
	token := gopaseto.NewToken()
	token.SetString("user", "alice")
	token.SetFooter([]byte(footer))

	return token.V4Encrypt(key, nil), key.ExportHex()
}

// TestDecodeWithFooterReturnsFooter covers the silent data loss: the footer is
// authenticated as part of the token, but nothing ever surfaced it, so an
// operator inspecting a third-party token had no way to see one was present.
func TestDecodeWithFooterReturnsFooter(t *testing.T) {
	const footer = `{"kid":"key-1"}`
	tokenString, keyHex := mintFooterToken(t, footer)

	codec, err := paseto.NewLocalV4Encoder(keyHex)
	if err != nil {
		t.Fatalf("Failed to build the codec: %v", err)
	}

	decoded, err := codec.DecodeWithFooter(tokenString)
	if err != nil {
		t.Fatalf("Expected the token to decode, got: %v", err)
	}
	if string(decoded.Footer) != footer {
		t.Errorf("Footer = %q, want %q", decoded.Footer, footer)
	}
	if !strings.Contains(decoded.Claims, "alice") {
		t.Errorf("Expected the claims to survive, got: %s", decoded.Claims)
	}
}

// TestDecodeDropsFooter pins that the older Decode keeps its exact contract, so
// no existing caller changes behaviour.
func TestDecodeDropsFooter(t *testing.T) {
	tokenString, keyHex := mintFooterToken(t, `{"kid":"key-1"}`)

	codec, err := paseto.NewLocalV4Encoder(keyHex)
	if err != nil {
		t.Fatalf("Failed to build the codec: %v", err)
	}

	claims, err := codec.Decode(tokenString)
	if err != nil {
		t.Fatalf("Expected the token to decode, got: %v", err)
	}
	if strings.Contains(claims, "kid") {
		t.Errorf("Decode should return claims only, got: %s", claims)
	}
}

// TestFooterlessTokenHasNilFooter keeps the common case honest: the tokens
// jwt-cli itself produces carry no footer, and must report none rather than an
// empty-but-present one.
func TestFooterlessTokenHasNilFooter(t *testing.T) {
	key := gopaseto.NewV4SymmetricKey()
	codec, err := paseto.NewLocalV4Encoder(key.ExportHex())
	if err != nil {
		t.Fatalf("Failed to build the codec: %v", err)
	}

	tokenString, err := codec.Encode(`{"user":"alice"}`)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	decoded, err := codec.DecodeWithFooter(tokenString)
	if err != nil {
		t.Fatalf("Expected the token to decode, got: %v", err)
	}
	if len(decoded.Footer) != 0 {
		t.Errorf("Expected no footer, got %q", decoded.Footer)
	}
}

// TestTamperedFooterIsRejected confirms the footer is inside the authenticated
// data, which is why surfacing it is safe: what a caller sees cannot have been
// altered in transit.
func TestTamperedFooterIsRejected(t *testing.T) {
	tokenString, keyHex := mintFooterToken(t, `{"kid":"key-1"}`)

	codec, err := paseto.NewLocalV4Encoder(keyHex)
	if err != nil {
		t.Fatalf("Failed to build the codec: %v", err)
	}

	segments := strings.Split(tokenString, ".")
	if len(segments) != 4 {
		t.Fatalf("Expected a four-segment footer'd token, got %d segments", len(segments))
	}

	t.Run("footer replaced", func(t *testing.T) {
		// A different footer, base64url encoded without padding.
		segments[3] = "eyJraWQiOiJhdHRhY2tlciJ9"
		if _, err := codec.DecodeWithFooter(strings.Join(segments, ".")); err == nil {
			t.Error("Expected a modified footer to fail verification")
		}
	})

	t.Run("footer stripped", func(t *testing.T) {
		if _, err := codec.DecodeWithFooter(strings.Join(segments[:3], ".")); err == nil {
			t.Error("Expected a stripped footer to fail verification")
		}
	})
}
