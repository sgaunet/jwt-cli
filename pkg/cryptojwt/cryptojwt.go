// Package cryptojwt provides JWT encoding and decoding functionality.
package cryptojwt

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Encoder is the interface for encoding JWT tokens.
type Encoder interface {
	Encode(payload string) (string, error)
}

// Decoder is the interface for decoding JWT tokens.
type Decoder interface {
	Decode(token string) (string, error)
}

// EncoderDecoder is the interface for encoding and decoding JWT tokens.
type EncoderDecoder interface {
	Encoder
	Decoder
}

type encoder struct {
}

type decoder struct {
}

func (e *encoder) EncodeJWT(secret any, signingMethod jwt.SigningMethod, payload string) (string, error) {
	claims := jwt.MapClaims{}
	err := json.Unmarshal([]byte(payload), &claims)
	if err != nil {
		return "", fmt.Errorf("payload is not a valid JSON: %w", err)
	}
	// Create token
	token := jwt.NewWithClaims(signingMethod, claims)
	// Generate encoded token and send it as response.
	t, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return t, nil
}

func (d *decoder) DecodeJWT(secret any, token string) (string, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
		return secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}
	res, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	return string(res), nil
}
