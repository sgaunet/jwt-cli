// Package claimtime converts numeric JSON date claims to time.Time under an
// explicit range bound.
//
// encoding/json decodes every JSON number into a float64, and converting one
// that lies outside int64 range is implementation-defined in Go. A claim of
// 9223372036854775807 therefore wraps to a far-past instant, and a token is
// reported as expired when the real fault is a nonsense timestamp.
package claimtime

import (
	"errors"
	"fmt"
	"time"
)

// The accepted range for a Unix-seconds timestamp.
const (
	// MaxSeconds is 9999-12-31T23:59:59Z: past any legitimate token lifetime,
	// and comfortably inside what int64 and time.Unix represent exactly.
	MaxSeconds = 253402300799
	// MinSeconds is 0001-01-01T00:00:00Z, the earliest instant time.Time holds.
	MinSeconds = -62135596800
)

// ErrOutOfRange indicates a numeric timestamp outside the accepted range.
// Callers wrap it in their own package's sentinel, so it stays matchable from
// outside internal/.
var ErrOutOfRange = errors.New("timestamp out of range")

// InRange reports whether seconds is an acceptable Unix-seconds timestamp.
//
// A NaN fails both comparisons and is correctly reported as out of range.
func InRange(seconds float64) bool {
	return seconds >= MinSeconds && seconds <= MaxSeconds
}

// FromSeconds converts a Unix-seconds timestamp, refusing one out of range
// rather than letting it wrap.
func FromSeconds(seconds float64) (time.Time, error) {
	if !InRange(seconds) {
		return time.Time{}, fmt.Errorf("%w: %g is outside %d..%d",
			ErrOutOfRange, seconds, MinSeconds, MaxSeconds)
	}
	return time.Unix(int64(seconds), 0).UTC(), nil
}
