package app

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

func EncodeJWT(secret []byte, method string, payload string) (string, error) {
	sigingMethod, err := GetSigningMethod(method)
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{}
	err = json.Unmarshal([]byte(payload), &claims)
	if err != nil {
		return "", fmt.Errorf("payload is not a valid JSON: %w", err)
	}
	// Create token
	token := jwt.NewWithClaims(sigingMethod, claims)
	// Generate encoded token and send it as response.
	t, err := token.SignedString(secret)
	return t, err
}

func GetSigningMethod(method string) (jwt.SigningMethod, error) {
	switch method {
	case "HS256":
		return jwt.SigningMethodHS256, nil
	case "HS384":
		return jwt.SigningMethodHS384, nil
	case "HS512":
		return jwt.SigningMethodHS512, nil
		// case "RS256":
		// 	return jwt.SigningMethodRS256, nil
		// case "RS384":
		// 	return jwt.SigningMethodRS384, nil
		// case "RS512":
		// 	return jwt.SigningMethodRS512, nil
		// case "ES256":
		// 	return jwt.SigningMethodES256, nil
		// case "ES384":
		// 	return jwt.SigningMethodES384, nil
		// case "ES512":
		// 	return jwt.SigningMethodES512, nil
	}
	return nil, fmt.Errorf("signing Method not found")
}

func PrintMethod(f *os.File) {
	fmt.Fprintln(f, "HS256")
	fmt.Fprintln(f, "HS384")
	fmt.Fprintln(f, "HS512")
	// fmt.Fprintln(f, "RS256")
	// fmt.Fprintln(f, "RS384")
	// fmt.Fprintln(f, "RS512")
	// fmt.Fprintln(f, "ES256")
	// fmt.Fprintln(f, "ES384")
	// fmt.Fprintln(f, "ES512")
}

func DecodeJWT(secret []byte, method, token string) (string, error) {
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
