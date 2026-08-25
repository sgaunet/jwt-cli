package cryptojwt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestUnknownHMACMethodFailsClosed exercises the defensive default branch in
// validateSecret. No exported constructor can reach it, so the test goes through
// the export_test.go bridge. The point is the direction of the failure: an
// unrecognised method must refuse to sign, not skip the secret-length check.
func TestUnknownHMACMethodFailsClosed(t *testing.T) {
	// A method the switch has no case for. RS256 is a real signing method, so
	// this is the shape a future mistake would take, not a synthetic stub.
	j := cryptojwt.NewHSEncoderDecoderWithMethod(jwt.SigningMethodRS256, []byte(strongSecret))

	t.Run("encode", func(t *testing.T) {
		_, err := j.Encode(`{"user":"alice"}`)
		if err == nil {
			t.Fatal("Expected an unknown signing method to be rejected, got nil")
		}
		if !errors.Is(err, cryptojwt.ErrUnsupportedAlgorithm) {
			t.Errorf("Expected errors.Is(err, ErrUnsupportedAlgorithm), got: %v", err)
		}
		if !strings.Contains(err.Error(), "RS256") {
			t.Errorf("Expected the error to name the offending method, got: %v", err)
		}
	})

	t.Run("decode", func(t *testing.T) {
		_, err := j.Decode("a.b.c")
		if err == nil {
			t.Fatal("Expected an unknown signing method to be rejected, got nil")
		}
		if !errors.Is(err, cryptojwt.ErrUnsupportedAlgorithm) {
			t.Errorf("Expected errors.Is(err, ErrUnsupportedAlgorithm), got: %v", err)
		}
	})
}
