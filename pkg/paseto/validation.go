package paseto

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ValidationOptions configures decode-time validation of time-based claims.
//
// It mirrors cryptojwt.ValidationOptions so the PASETO and JWT decode commands
// expose the same --validate-claims and --clock-skew semantics.
type ValidationOptions struct {
	// ValidateClaims enables validation of the time-based claims exp and nbf.
	// When false, a token is accepted regardless of its timing claims.
	ValidateClaims bool
	// ClockSkew allows tolerance for clock differences between the issuer and
	// this machine. Applied to both exp and nbf. Default is 0 (no tolerance).
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
		if time.Now().After(exp.Add(tolerance)) {
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
		if time.Now().Add(tolerance).Before(nbf) {
			return fmt.Errorf("%w (nbf %s)", ErrTokenNotYetValid, nbf.Format(time.RFC3339))
		}
		return nil
	}
}
