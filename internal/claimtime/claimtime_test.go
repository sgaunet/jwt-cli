package claimtime_test

import (
	"errors"
	"math"
	"testing"

	"github.com/sgaunet/jwt-cli/internal/claimtime"
)

// TestInRange pins the accepted bounds, including the values that motivated the
// check: converting a float64 outside int64 range is implementation-defined in
// Go, so an unchecked exp of math.MaxInt64 wrapped to a far-past instant.
func TestInRange(t *testing.T) {
	tests := []struct {
		name    string
		seconds float64
		want    bool
	}{
		{"a plausible timestamp", 1735689600, true},
		{"zero", 0, true},
		{"the maximum", claimtime.MaxSeconds, true},
		{"one past the maximum", claimtime.MaxSeconds + 1, false},
		{"the minimum", claimtime.MinSeconds, true},
		{"one before the minimum", claimtime.MinSeconds - 1, false},
		{"max int64 as a float", math.MaxInt64, false},
		{"min int64 as a float", math.MinInt64, false},
		{"1e30", 1e30, false},
		{"negative 9e18", -9e18, false},
		{"positive infinity", math.Inf(1), false},
		{"negative infinity", math.Inf(-1), false},
		{"NaN", math.NaN(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claimtime.InRange(tt.seconds); got != tt.want {
				t.Errorf("InRange(%g) = %v, want %v", tt.seconds, got, tt.want)
			}
		})
	}
}

// TestFromSeconds checks the conversion and the refusal, and that an accepted
// value round-trips to the instant it names.
func TestFromSeconds(t *testing.T) {
	t.Run("converts an in-range value", func(t *testing.T) {
		got, err := claimtime.FromSeconds(1735689600)
		if err != nil {
			t.Fatalf("Expected the conversion to succeed, got: %v", err)
		}
		if got.Unix() != 1735689600 {
			t.Errorf("Unix() = %d, want 1735689600", got.Unix())
		}
	})

	t.Run("refuses an out-of-range value", func(t *testing.T) {
		_, err := claimtime.FromSeconds(math.MaxInt64)
		if err == nil {
			t.Fatal("Expected an out-of-range error, got nil")
		}
		if !errors.Is(err, claimtime.ErrOutOfRange) {
			t.Errorf("Expected ErrOutOfRange, got: %v", err)
		}
	})

	t.Run("the boundary itself converts", func(t *testing.T) {
		got, err := claimtime.FromSeconds(claimtime.MaxSeconds)
		if err != nil {
			t.Fatalf("Expected the maximum to be accepted, got: %v", err)
		}
		if got.Year() != 9999 {
			t.Errorf("Year() = %d, want 9999", got.Year())
		}
	})
}
