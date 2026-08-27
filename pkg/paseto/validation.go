package paseto

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ValidationOptions configures decode-time validation of time-based claims.
//
// It mirrors cryptojwt.ValidationOptions, so the PASETO and JWT decode commands
// take the same --validate-claims and --clock-skew flags with the same defaults
// and the same exp and nbf boundaries. The rules differ in one respect: the JWT
// path also rejects a future-dated iat, which PASETO has no rule for.
type ValidationOptions struct {
	// ValidateClaims enables validation of the time-based claims exp and nbf.
	// When false, a token is accepted regardless of its timing claims.
	ValidateClaims bool
	// ClockSkew allows tolerance for clock differences between the issuer and
	// this machine. Applied to both exp and nbf. Default is 0 (no tolerance).
	// A negative value tightens the window instead of widening it; the jwt-cli
	// paseto decode commands refuse one.
	ClockSkew time.Duration
}

// Option configures an encoder/decoder built by this package.
type Option func(*validator)

// WithValidation enables decode-time validation of time-based claims.
//
// It has no effect on Encode.
func WithValidation(v ValidationOptions) Option {
	return func(val *validator) {
		val.opts = v
	}
}

// validator holds the decode-time validation settings shared by every
// encoder/decoder in this package, which embed it.
type validator struct {
	opts ValidationOptions
}

// newValidator applies opts, yielding the zero value - no validation, the
// package default - when none are given.
func newValidator(opts []Option) validator {
	var v validator
	for _, opt := range opts {
		opt(&v)
	}
	return v
}

// parser returns the go-paseto parser matching the configured options.
//
// Without validation the parser carries no rules at all, so a token is accepted
// on its signature or authentication tag alone.
func (v validator) parser() paseto.Parser {
	if !v.opts.ValidateClaims {
		return paseto.NewParserWithoutExpiryCheck()
	}
	return paseto.MakeParser([]paseto.Rule{
		notExpired(v.opts.ClockSkew),
		notBefore(v.opts.ClockSkew),
	})
}

// isExpired reports whether now has reached exp, allowing skew of tolerance.
//
// The bound is inclusive of exp itself: RFC 7519 section 4.1.4 requires the
// current time to be strictly before exp, so a token whose exp equals now is
// expired. golang-jwt's validator uses the same bound, which keeps the JWT and
// PASETO decode paths on one boundary rather than differing by a second.
//
// It is a separate function because notExpired reads time.Now() inline, which
// leaves the instant of the boundary unreachable from a test.
func isExpired(now, exp time.Time, tolerance time.Duration) bool {
	return !now.Before(exp.Add(tolerance))
}

// isNotYetValid reports whether nbf still lies ahead of now, allowing skew of
// tolerance.
//
// The bound is exclusive of nbf itself: RFC 7519 section 4.1.5 requires the
// current time to be at or after nbf, so a token whose nbf equals now is valid.
// This already matched golang-jwt and is unchanged.
func isNotYetValid(now, nbf time.Time, tolerance time.Duration) bool {
	return now.Add(tolerance).Before(nbf)
}

// notExpired rejects a token whose exp claim has passed, allowing skew of
// tolerance.
//
// A token carrying no exp claim passes: there is nothing to enforce. This
// matches the JWT decode commands, and differs from go-paseto's own
// paseto.NotExpired rule, which treats an absent exp as a failure.
func notExpired(tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		if _, present := token.Claims()[claimExpiration]; !present {
			return nil
		}
		exp, err := token.GetExpiration()
		if err != nil {
			return fmt.Errorf("%w: %q is not a usable timestamp: %w", ErrInvalidClaim, claimExpiration, err)
		}
		if isExpired(time.Now(), exp, tolerance) {
			return fmt.Errorf("%w (exp %s)", ErrTokenExpired, exp.Format(time.RFC3339))
		}
		return nil
	}
}

// notBefore rejects a token whose nbf claim has not been reached, allowing skew
// of tolerance.
//
// As with notExpired, an absent nbf claim passes.
func notBefore(tolerance time.Duration) paseto.Rule {
	return func(token paseto.Token) error {
		if _, present := token.Claims()[claimNotBefore]; !present {
			return nil
		}
		nbf, err := token.GetNotBefore()
		if err != nil {
			return fmt.Errorf("%w: %q is not a usable timestamp: %w", ErrInvalidClaim, claimNotBefore, err)
		}
		if isNotYetValid(time.Now(), nbf, tolerance) {
			return fmt.Errorf("%w (nbf %s)", ErrTokenNotYetValid, nbf.Format(time.RFC3339))
		}
		return nil
	}
}
