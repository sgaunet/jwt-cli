package cmd

import (
	"errors"
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/app"
)

func CheckArguments(secret, token, method string) error {
	if secret == "" {
		return errors.New("secret is required")
	}
	// if token == "" {
	// 	return errors.New("token is required")
	// }
	if method == "" {
		return errors.New("method is required")
	}
	_, err := app.GetSigningMethod(method)
	if err != nil {
		return fmt.Errorf("invalid signing method: %v", err.Error())
	}
	return nil
}
