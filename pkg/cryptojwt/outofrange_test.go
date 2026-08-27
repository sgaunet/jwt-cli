package cryptojwt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// rangeTestSecret is long enough for HS256's RFC 7518 minimum.
const rangeTestSecret = "range-test-secret-key-hs256-32by"

// TestOutOfRangeTimeClaimIsReportedAsSuch covers the misdiagnosis an unchecked
// narrowing produced.
//
// golang-jwt converts a claim's float64 to int64 without a range check, so an
// exp of math.MaxInt64 wrapped to a far-past instant and the token came back as
// "token is expired" - the wrong answer for a timestamp that names no real
// moment at all.
func TestOutOfRangeTimeClaimIsReportedAsSuch(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"exp at max int64", `{"user":"alice","exp":9223372036854775807}`},
		{"exp far beyond any date", `{"user":"alice","exp":1e30}`},
		{"nbf at max int64", `{"user":"alice","nbf":9223372036854775807}`},
		{"iat far in the negative", `{"user":"alice","iat":-9e18}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := cryptojwt.NewHS256EncoderWithOptions([]byte(rangeTestSecret), false)
			token, err := encoder.Encode(tt.payload)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			decoder := cryptojwt.NewHS256DecoderWithValidation(
				[]byte(rangeTestSecret), false,
				cryptojwt.ValidationOptions{ValidateClaims: true})

			claims, decodeErr := decoder.Decode(token)
			if decodeErr == nil {
				t.Fatalf("Expected the token to be rejected, got claims: %s", claims)
			}
			if !errors.Is(decodeErr, cryptojwt.ErrClaimOutOfRange) {
				t.Errorf("Expected ErrClaimOutOfRange, got: %v", decodeErr)
			}
			if strings.Contains(decodeErr.Error(), "expired") {
				t.Errorf("Expected no misleading expiry wording, got: %v", decodeErr)
			}
		})
	}
}

// TestSignatureFailureOutranksRangeReport is the guard on the reclassification.
//
// The range check runs only when claims validation is what failed. Without that
// condition, a token whose signature did not verify but which happens to carry a
// nonsense exp would be reported as a malformed claim - hiding the fact that the
// signature was invalid, on the one path where the message matters most.
func TestSignatureFailureOutranksRangeReport(t *testing.T) {
	encoder := cryptojwt.NewHS256EncoderWithOptions([]byte(rangeTestSecret), false)
	token, err := encoder.Encode(`{"user":"alice","exp":9223372036854775807}`)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	wrongSecret := []byte("a-completely-different-secret-32")
	decoder := cryptojwt.NewHS256DecoderWithValidation(
		wrongSecret, false, cryptojwt.ValidationOptions{ValidateClaims: true})

	_, decodeErr := decoder.Decode(token)
	if decodeErr == nil {
		t.Fatal("Expected the token to be rejected")
	}
	if !errors.Is(decodeErr, jwt.ErrSignatureInvalid) {
		t.Errorf("Expected the signature failure to be reported, got: %v", decodeErr)
	}
	if errors.Is(decodeErr, cryptojwt.ErrClaimOutOfRange) {
		t.Error("A signature failure must not be reported as a claim range problem")
	}
}

// TestInRangeClaimsUnaffected keeps the check from touching ordinary tokens.
func TestInRangeClaimsUnaffected(t *testing.T) {
	encoder := cryptojwt.NewHS256EncoderWithOptions([]byte(rangeTestSecret), false)
	// Year 2038 and change: comfortably valid, and past the 32-bit boundary.
	token, err := encoder.Encode(`{"user":"alice","exp":2200000000}`)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	decoder := cryptojwt.NewHS256DecoderWithValidation(
		[]byte(rangeTestSecret), false,
		cryptojwt.ValidationOptions{ValidateClaims: true})

	claims, err := decoder.Decode(token)
	if err != nil {
		t.Fatalf("Expected the token to decode, got: %v", err)
	}
	if !strings.Contains(claims, "alice") {
		t.Errorf("Expected the claims to survive, got: %s", claims)
	}
}
