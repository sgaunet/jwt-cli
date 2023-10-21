package cryptojwt

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Encoder interface {
	Encode(payload string) (string, error)
}

type Decoder interface {
	Decode(token string) (string, error)
}

type EncoderDecoder interface {
	Encoder
	Decoder
}

type encoder struct {
}

type decoder struct {
}

func (e *encoder) EncodeJWT(secret interface{}, signingMethod jwt.SigningMethod, payload string) (string, error) {
	claims := jwt.MapClaims{}
	err := json.Unmarshal([]byte(payload), &claims)
	if err != nil {
		return "", fmt.Errorf("payload is not a valid JSON: %w", err)
	}
	// Create token
	token := jwt.NewWithClaims(signingMethod, claims)
	// Generate encoded token and send it as response.
	t, err := token.SignedString(secret)
	return t, err
}

func (d *decoder) DecodeJWT(secret interface{}, token string) (string, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return "", err
	}
	res, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return "", err
	}
	return string(res), nil
}
