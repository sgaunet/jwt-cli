package paseto

import (
	"encoding/json"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// Registered PASETO claim names that receive dedicated handling.
const (
	claimExpiration = "exp"
	claimNotBefore  = "nbf"
	claimIssuedAt   = "iat"
	claimIssuer     = "iss"
	claimSubject    = "sub"
	claimAudience   = "aud"
	claimTokenID    = "jti"
)

// parsePayload decodes a JSON payload into a claim map, rejecting anything that
// is not a JSON object.
func parsePayload(payload string) (map[string]any, error) {
	if err := validateJSONPayload(payload); err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	return data, nil
}

// parseClaimTime interprets a time-based registered claim.
//
// Two forms are accepted: an RFC 3339 string, and a numeric Unix timestamp in
// seconds (the form conventionally used by JWT payloads). Any other value is an
// error, so a mistyped or misformatted claim is reported rather than dropped.
func parseClaimTime(claim string, value any) (time.Time, error) {
	switch v := value.(type) {
	case string:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, fmt.Errorf(
				"%w: %q must be an RFC 3339 timestamp or a Unix timestamp, got %q",
				ErrInvalidClaim, claim, v)
		}
		return t, nil
	case float64:
		// encoding/json decodes every JSON number into a float64.
		return time.Unix(int64(v), 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf(
			"%w: %q must be an RFC 3339 timestamp or a Unix timestamp, got %T",
			ErrInvalidClaim, claim, value)
	}
}

// parseClaimString interprets a string-valued registered claim.
func parseClaimString(claim string, value any) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q must be a string, got %T", ErrInvalidClaim, claim, value)
	}
	return s, nil
}

// applyClaims copies data onto token, mapping the PASETO registered claims onto
// their dedicated setters and every other key onto a custom claim.
//
// token must be a pointer: paseto.NewToken returns a value and every setter has
// a pointer receiver.
func applyClaims(token *paseto.Token, data map[string]any) error {
	for key, value := range data {
		if err := applyClaim(token, key, value); err != nil {
			return err
		}
	}
	return nil
}

// applyClaim copies a single claim onto token.
func applyClaim(token *paseto.Token, key string, value any) error {
	switch key {
	case claimExpiration, claimNotBefore, claimIssuedAt:
		t, err := parseClaimTime(key, value)
		if err != nil {
			return err
		}
		setTimeClaim(token, key, t)
	case claimIssuer, claimSubject, claimAudience, claimTokenID:
		s, err := parseClaimString(key, value)
		if err != nil {
			return err
		}
		setStringClaim(token, key, s)
	default:
		if err := token.Set(key, value); err != nil {
			return fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}
	return nil
}

// setTimeClaim dispatches a parsed time onto the matching PASETO setter.
func setTimeClaim(token *paseto.Token, key string, t time.Time) {
	switch key {
	case claimExpiration:
		token.SetExpiration(t)
	case claimNotBefore:
		token.SetNotBefore(t)
	case claimIssuedAt:
		token.SetIssuedAt(t)
	}
}

// setStringClaim dispatches a string onto the matching PASETO setter.
func setStringClaim(token *paseto.Token, key, value string) {
	switch key {
	case claimIssuer:
		token.SetIssuer(value)
	case claimSubject:
		token.SetSubject(value)
	case claimAudience:
		token.SetAudience(value)
	case claimTokenID:
		token.SetJti(value)
	}
}

// newTokenFromPayload builds a PASETO token carrying the claims in payload.
func newTokenFromPayload(payload string) (paseto.Token, error) {
	data, err := parsePayload(payload)
	if err != nil {
		return paseto.Token{}, err
	}
	token := paseto.NewToken()
	if err := applyClaims(&token, data); err != nil {
		return paseto.Token{}, err
	}
	return token, nil
}

// claimsJSON renders a decoded token's claims as indented JSON.
func claimsJSON(token *paseto.Token) (string, error) {
	jsonBytes, err := json.MarshalIndent(token.Claims(), "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	return string(jsonBytes), nil
}
