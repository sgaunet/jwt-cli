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
	validationOpts  ValidationOptions
}

// validateSecretLength validates that the secret meets minimum length requirements.
func validateSecretLength(secret []byte, minLength int, algorithm string) error {
	if len(secret) < minLength {
		return fmt.Errorf("weak secret: %s requires a minimum of %d bytes (got %d bytes). Use --allow-weak-secret flag to bypass this check for testing purposes only", algorithm, minLength, len(secret))
	}
	return nil
}

// NewHS256Encoder creates a new HMAC-SHA256 JWT encoder/decoder.
//
// Security: The secret should be at least 256 bits (32 bytes) for HS256.
// Weak secrets are vulnerable to brute-force attacks. By default, this function
// enforces minimum secret length according to RFC 7518. Use NewHS256EncoderWithOptions
// with allowWeakSecret=true only for testing purposes.
//
// Example:
//
//	secret := []byte("my-32-byte-secret-key-for-hs256")
//	encoder := cryptojwt.NewHS256Encoder(secret)
//	token, err := encoder.Encode(`{"user":"alice","exp":1735689600}`)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(token) // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
func NewHS256Encoder(secret []byte) EncoderDecoder {
	return NewHS256EncoderWithOptions(secret, false)
}

// NewHS256EncoderWithOptions creates a new HMAC-SHA256 JWT encoder/decoder with options.
//
// Parameters:
//   - secret: The shared secret key (minimum 32 bytes recommended)
//   - allowWeakSecret: If true, allows secrets shorter than 32 bytes (TESTING ONLY)
//
// Security: Setting allowWeakSecret=true bypasses RFC 7518 security requirements.
// Only use this for testing with non-production data.
func NewHS256EncoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS256EncoderWithValidation(secret, allowWeakSecret, ValidationOptions{})
}

// NewHS256EncoderWithValidation creates a new HMAC-SHA256 JWT encoder/decoder with validation options.
//
// Parameters:
//   - secret: The shared secret key (minimum 32 bytes recommended)
//   - allowWeakSecret: If true, allows secrets shorter than 32 bytes (TESTING ONLY)
//   - validationOpts: Options for validating JWT claims (exp, nbf, iat)
//
// Note: By default, time-based claims (exp, nbf, iat) are NOT validated.
// Set validationOpts.ValidateClaims=true to enable automatic expiration checking.
func NewHS256EncoderWithValidation(secret []byte, allowWeakSecret bool, validationOpts ValidationOptions) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method:          jwt.SigningMethodHS256,
		secret:          secret,
		allowWeakSecret: allowWeakSecret,
		validationOpts:  validationOpts,
		decoder:         decoder{validationOpts: validationOpts},
	}
}

// NewHS256Decoder creates a new HMAC-SHA256 JWT decoder.
func NewHS256Decoder(secret []byte) EncoderDecoder {
	return NewHS256DecoderWithOptions(secret, false)
}

// NewHS256DecoderWithOptions creates a new HMAC-SHA256 JWT decoder with options.
func NewHS256DecoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS256EncoderWithValidation(secret, allowWeakSecret, ValidationOptions{})
}

// NewHS256DecoderWithValidation creates a new HMAC-SHA256 JWT decoder with validation options.
func NewHS256DecoderWithValidation(secret []byte, allowWeakSecret bool, validationOpts ValidationOptions) EncoderDecoder {
	return NewHS256EncoderWithValidation(secret, allowWeakSecret, validationOpts)
}

// NewHS384Encoder creates a new HMAC-SHA384 JWT encoder/decoder.
//
// Security: The secret should be at least 384 bits (48 bytes) for HS384.
// Weak secrets are vulnerable to brute-force attacks. By default, this function
// enforces minimum secret length according to RFC 7518.
func NewHS384Encoder(secret []byte) EncoderDecoder {
	return NewHS384EncoderWithOptions(secret, false)
}

// NewHS384EncoderWithOptions creates a new HMAC-SHA384 JWT encoder/decoder with options.
func NewHS384EncoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS384EncoderWithValidation(secret, allowWeakSecret, ValidationOptions{})
}

// NewHS384EncoderWithValidation creates a new HMAC-SHA384 JWT encoder/decoder with validation options.
func NewHS384EncoderWithValidation(secret []byte, allowWeakSecret bool, validationOpts ValidationOptions) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method:          jwt.SigningMethodHS384,
		secret:          secret,
		allowWeakSecret: allowWeakSecret,
		validationOpts:  validationOpts,
		decoder:         decoder{validationOpts: validationOpts},
	}
}

// NewHS384Decoder creates a new HMAC-SHA384 JWT decoder.
func NewHS384Decoder(secret []byte) EncoderDecoder {
	return NewHS384DecoderWithOptions(secret, false)
}

// NewHS384DecoderWithOptions creates a new HMAC-SHA384 JWT decoder with options.
func NewHS384DecoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS384EncoderWithValidation(secret, allowWeakSecret, ValidationOptions{})
}

// NewHS384DecoderWithValidation creates a new HMAC-SHA384 JWT decoder with validation options.
func NewHS384DecoderWithValidation(secret []byte, allowWeakSecret bool, validationOpts ValidationOptions) EncoderDecoder {
	return NewHS384EncoderWithValidation(secret, allowWeakSecret, validationOpts)
}

// NewHS512Encoder creates a new HMAC-SHA512 JWT encoder/decoder.
//
// Security: The secret should be at least 512 bits (64 bytes) for HS512.
// Weak secrets are vulnerable to brute-force attacks. By default, this function
// enforces minimum secret length according to RFC 7518.
func NewHS512Encoder(secret []byte) EncoderDecoder {
	return NewHS512EncoderWithOptions(secret, false)
}

// NewHS512EncoderWithOptions creates a new HMAC-SHA512 JWT encoder/decoder with options.
func NewHS512EncoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS512EncoderWithValidation(secret, allowWeakSecret, ValidationOptions{})
}

// NewHS512EncoderWithValidation creates a new HMAC-SHA512 JWT encoder/decoder with validation options.
func NewHS512EncoderWithValidation(secret []byte, allowWeakSecret bool, validationOpts ValidationOptions) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method:          jwt.SigningMethodHS512,
		secret:          secret,
		allowWeakSecret: allowWeakSecret,
		validationOpts:  validationOpts,
		decoder:         decoder{validationOpts: validationOpts},
	}
}

// NewHS512Decoder creates a new HMAC-SHA512 JWT decoder.
func NewHS512Decoder(secret []byte) EncoderDecoder {
	return NewHS512DecoderWithOptions(secret, false)
}

// NewHS512DecoderWithOptions creates a new HMAC-SHA512 JWT decoder with options.
func NewHS512DecoderWithOptions(secret []byte, allowWeakSecret bool) EncoderDecoder {
	return NewHS512EncoderWithValidation(secret, allowWeakSecret, ValidationOptions{})
}

// NewHS512DecoderWithValidation creates a new HMAC-SHA512 JWT decoder with validation options.
func NewHS512DecoderWithValidation(secret []byte, allowWeakSecret bool, validationOpts ValidationOptions) EncoderDecoder {
	return NewHS512EncoderWithValidation(secret, allowWeakSecret, validationOpts)
}

// Decode validates and decodes a JWT token using HMAC algorithm.
//
// Security: This function validates that the token's algorithm matches the expected
// HMAC algorithm to prevent algorithm confusion attacks. Tokens signed with different
// algorithms will be rejected.
//
// Note: By default, time-based claims (exp, nbf, iat) are NOT validated. Use
// NewHS*EncoderWithValidation with ValidationOptions.ValidateClaims=true to enable
// automatic expiration checking.
//
// Returns: JSON string representation of the token's claims, or an error if validation fails.
func (j *hsjwtEncoderDecoder) Decode(token string) (string, error) {
	if !j.allowWeakSecret {
		if err := j.validateSecret(); err != nil {
			return "", err
		}
	}
	return j.decoder.DecodeJWT(j.secret, token)
}

// Encode creates and signs a JWT token using HMAC algorithm.
//
// The payload must be a valid JSON string that can be unmarshaled into jwt.MapClaims.
//
// Security: The returned token is signed but NOT encrypted. Do not include sensitive
// data (passwords, API keys, PII) in the payload as it can be decoded by anyone.
// Always transmit JWT tokens over HTTPS.
//
// Example payload:
//
//	`{"user_id":"12345","role":"admin","exp":1735689600}`
//
// Returns: Base64-encoded JWT token (header.payload.signature) or an error if signing fails.
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
