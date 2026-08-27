package paseto_test

import (
	"testing"
	"time"

	"github.com/sgaunet/jwt-cli/pkg/paseto"
)

// TestExpiryBoundary pins the exact instant at which a token expires.
//
// The exp bound used to be exclusive here (time.Now().After(exp)) while the JWT
// path's was inclusive, so a token whose exp equalled the current second was
// accepted by "paseto decode" and rejected by "decode" - a one-second
// divergence between two paths the README describes as having the same meaning.
// RFC 7519 section 4.1.4 requires the current time to be strictly before exp.
//
// These call the predicates directly because the rules read time.Now() inline:
// through Decode the boundary instant is unreachable, and a wall-clock test
// could not tell the old behaviour from the new.
func TestExpiryBoundary(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		exp       time.Time
		tolerance time.Duration
		want      bool
	}{
		{"exp equal to now is expired", now, 0, true},
		{"exp one nanosecond ahead is not expired", now.Add(time.Nanosecond), 0, false},
		{"exp one second ahead is not expired", now.Add(time.Second), 0, false},
		{"exp one second past is expired", now.Add(-time.Second), 0, true},
		{"exp plus tolerance equal to now is expired", now.Add(-time.Minute), time.Minute, true},
		{"exp inside tolerance is not expired", now.Add(-time.Minute), 2 * time.Minute, false},
		{"exp outside tolerance is expired", now.Add(-10 * time.Minute), time.Minute, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := paseto.IsExpired(now, tt.exp, tt.tolerance); got != tt.want {
				t.Errorf("IsExpired(now, %v, %v) = %v, want %v", tt.exp, tt.tolerance, got, tt.want)
			}
		})
	}
}

// TestNotBeforeBoundary pins the nbf bound, which is exclusive: RFC 7519
// section 4.1.5 requires the current time to be at or after nbf, so a token
// whose nbf equals now is already valid. This matched golang-jwt before the exp
// change and still does.
func TestNotBeforeBoundary(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		nbf       time.Time
		tolerance time.Duration
		want      bool
	}{
		{"nbf equal to now is valid", now, 0, false},
		{"nbf one nanosecond ahead is not yet valid", now.Add(time.Nanosecond), 0, true},
		{"nbf in the past is valid", now.Add(-time.Hour), 0, false},
		{"nbf inside tolerance is valid", now.Add(time.Minute), 2 * time.Minute, false},
		{"nbf outside tolerance is not yet valid", now.Add(10 * time.Minute), time.Minute, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := paseto.IsNotYetValid(now, tt.nbf, tt.tolerance); got != tt.want {
				t.Errorf("IsNotYetValid(now, %v, %v) = %v, want %v", tt.nbf, tt.tolerance, got, tt.want)
			}
		})
	}
}
