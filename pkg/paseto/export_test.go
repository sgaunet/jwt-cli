package paseto

import "time"

// IsExpired and IsNotYetValid expose the pure boundary predicates behind the exp
// and nbf rules, so the black-box tests in package paseto_test can pin the
// inclusive and exclusive bounds without racing the wall clock.
//
// The rules themselves read time.Now() inline, which makes the instant of the
// boundary - exp exactly equal to now - unreachable through Decode. Declaring
// these in a _test.go file keeps them out of the package's real API surface.
func IsExpired(now, exp time.Time, tolerance time.Duration) bool {
	return isExpired(now, exp, tolerance)
}

func IsNotYetValid(now, nbf time.Time, tolerance time.Duration) bool {
	return isNotYetValid(now, nbf, tolerance)
}
