package cryptojwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// Minimum secret lengths according to RFC 7518 Section 3.2.
	minHS256SecretLength = 32 // 256 bits
	minHS384SecretLength = 48 // 384 bits
	minHS512SecretLength = 64 // 512 bits
)

type hsjwtEncoderDecoder struct {
	encoder         encoder
	decoder         decoder
	secret          []byte
	method          jwt.SigningMethod
	allowWeakSecret bool
}

// validateSecretLength validates that the secret meets minimum length requirements.
func validateSecretLength(secret []byte, minLength int, algorithm string) error {
	if len(secret) < minLength {
		return fmt.Errorf("weak secret: %s requires a minimum of %d bytes (got %d bytes). Use --allow-weak-secret flag to bypass this check for testing purposes only", algorithm, minLength, len(secret))
	}
	return nil
}

// NewHS256Encoder creates a new HMAC-SHA256 JWT encoder/decoder.
func NewHS256Encoder(secret []byte) EncoderDecoder {
	return NewHS256EncoderWithOptions(secret, false)
}

// NewHS256EncoderWithOptions creates a new HMAC-SHA256 JWT encoder/decoder with options.
func NewHS256EncoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method:          jwt.SigningMethodHS256,
		secret:          secret,
		allowWeakSecret: allowWeakSecret,
	}
}

// NewHS256Decoder creates a new HMAC-SHA256 JWT decoder.
func NewHS256Decoder(secret []byte) EncoderDecoder {
	return NewHS256DecoderWithOptions(secret, false)
}

// NewHS256DecoderWithOptions creates a new HMAC-SHA256 JWT decoder with options.
func NewHS256DecoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS256EncoderWithOptions(secret, allowWeakSecret)
}

// NewHS384Encoder creates a new HMAC-SHA384 JWT encoder/decoder.
func NewHS384Encoder(secret []byte) EncoderDecoder {
	return NewHS384EncoderWithOptions(secret, false)
}

// NewHS384EncoderWithOptions creates a new HMAC-SHA384 JWT encoder/decoder with options.
func NewHS384EncoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method:          jwt.SigningMethodHS384,
		secret:          secret,
		allowWeakSecret: allowWeakSecret,
	}
}

// NewHS384Decoder creates a new HMAC-SHA384 JWT decoder.
func NewHS384Decoder(secret []byte) EncoderDecoder {
	return NewHS384DecoderWithOptions(secret, false)
}

// NewHS384DecoderWithOptions creates a new HMAC-SHA384 JWT decoder with options.
func NewHS384DecoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS384EncoderWithOptions(secret, allowWeakSecret)
}

// NewHS512Encoder creates a new HMAC-SHA512 JWT encoder/decoder.
func NewHS512Encoder(secret []byte) EncoderDecoder {
	return NewHS512EncoderWithOptions(secret, false)
}

// NewHS512EncoderWithOptions creates a new HMAC-SHA512 JWT encoder/decoder with options.
func NewHS512EncoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method:          jwt.SigningMethodHS512,
		secret:          secret,
		allowWeakSecret: allowWeakSecret,
	}
}

// NewHS512Decoder creates a new HMAC-SHA512 JWT decoder.
func NewHS512Decoder(secret []byte) EncoderDecoder {
	return NewHS512DecoderWithOptions(secret, false)
}

// NewHS512DecoderWithOptions creates a new HMAC-SHA512 JWT decoder with options.
func NewHS512DecoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS512EncoderWithOptions(secret, allowWeakSecret)
}

func (j *hsjwtEncoderDecoder) Decode(token string) (string, error) {
	if !j.allowWeakSecret {
		if err := j.validateSecret(); err != nil {
			return "", err
		}
	}
	return j.decoder.DecodeJWT(j.secret, token)
}

func (j *hsjwtEncoderDecoder) Encode(payload string) (string, error) {
	if !j.allowWeakSecret {
		if err := j.validateSecret(); err != nil {
			return "", err
		}
	}
	return j.encoder.EncodeJWT(j.secret, j.method, payload)
}

// validateSecret validates the secret based on the signing method.
func (j *hsjwtEncoderDecoder) validateSecret() error {
	switch j.method {
	case jwt.SigningMethodHS256:
		return validateSecretLength(j.secret, minHS256SecretLength, "HS256")
	case jwt.SigningMethodHS384:
		return validateSecretLength(j.secret, minHS384SecretLength, "HS384")
	case jwt.SigningMethodHS512:
		return validateSecretLength(j.secret, minHS512SecretLength, "HS512")
	default:
		return fmt.Errorf("unknown HMAC signing method: %v", j.method)
	}
}
