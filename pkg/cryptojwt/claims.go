package cryptojwt

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/internal/claimtime"
)

// timeClaims are the claims golang-jwt's validator reads as numeric dates.
var timeClaims = []string{"exp", "nbf", "iat"}

// checkTimeClaimRange rejects a token carrying a numeric time claim that cannot
// be represented as a Unix timestamp, once its claims are known to be
// trustworthy.
//
// parseErr is the error ParseWithClaims returned, and decides whether looking at
// claims is sound at all. golang-jwt verifies the signature before it validates
// claims, so the map holds cryptographically sound data in exactly two cases:
// the parse succeeded, or it failed on claims validation. Any other failure -
// an invalid signature above all - must be reported as itself, not as a
// malformed claim.
//
// Both of those cases matter, because the direction the wrap lands in is
// arbitrary: an out-of-range exp reads as long past and the token is rejected as
// expired, while an out-of-range nbf reads the same way and the token is
// *accepted*. Checking only the failure path would catch the first and miss the
// second.
//
// Nothing is checked unless claims validation was asked for: the default mode
// exists so that any token can be inspected, however nonsensical its claims.
func (d *decoder) checkTimeClaimRange(claims jwt.MapClaims, parseErr error) error {
	if !d.validationOpts.ValidateClaims {
		return nil
	}
	if parseErr != nil && !errors.Is(parseErr, jwt.ErrTokenInvalidClaims) {
		return nil
	}
	if rangeErr := outOfRangeTimeClaim(claims); rangeErr != nil {
		return fmt.Errorf("%w: %w", ErrInvalidToken, rangeErr)
	}
	return nil
}

// outOfRangeTimeClaim reports the first time claim holding a numeric value that
// cannot be represented as a Unix timestamp.
//
// golang-jwt converts a claim's float64 to int64 with no range check, so an exp
// of 9223372036854775807 wraps to a far-past instant and the token is reported
// as *expired* - the wrong diagnosis for what is really a malformed claim.
func outOfRangeTimeClaim(claims jwt.MapClaims) error {
	for _, claim := range timeClaims {
		seconds, ok := claims[claim].(float64)
		if ok && !claimtime.InRange(seconds) {
			return fmt.Errorf("%w: %q is %g, outside %d..%d",
				ErrClaimOutOfRange, claim, seconds,
				claimtime.MinSeconds, claimtime.MaxSeconds)
		}
	}
	return nil
}
