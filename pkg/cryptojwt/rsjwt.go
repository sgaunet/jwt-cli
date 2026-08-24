package cryptojwt

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/internal/keyfile"
)

// minRSAKeyBits is the smallest RSA modulus accepted for RS256/RS384/RS512.
// Shorter moduli are factorable within reach of a motivated attacker, so a key
// below this floor is rejected unless the caller explicitly opts out.
const minRSAKeyBits = 2048

type rsjwtEncoderWithPrivateKeyFile struct {
	encoder        encoder
	privateKeyFile string
	method         jwt.SigningMethod
	allowWeakKey   bool
}

type rsjwtDecoderWithPrivateKeyFile struct {
	decoder        decoder
	privateKeyFile string
	method         jwt.SigningMethod
	allowWeakKey   bool
}

type rsjwtDecoderWithPublicKeyFile struct {
	decoder       decoder
	publicKeyFile string
	method        jwt.SigningMethod
	allowWeakKey  bool
}

// newRSEncoder builds the encoder shared by every RS* constructor.
func newRSEncoder(method jwt.SigningMethod, privateKeyFile string, allowWeakKey bool) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         method,
		privateKeyFile: privateKeyFile,
		allowWeakKey:   allowWeakKey,
	}
}

// newRSDecoderWithPrivateKey builds the private-key decoder shared by every RS* constructor.
func newRSDecoderWithPrivateKey(
	method jwt.SigningMethod, privateKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         method,
		privateKeyFile: privateKeyFile,
		decoder:        decoder{validationOpts: validationOpts},
		allowWeakKey:   allowWeakKey,
	}
}

// newRSDecoderWithPublicKey builds the public-key decoder shared by every RS* constructor.
func newRSDecoderWithPublicKey(
	method jwt.SigningMethod, publicKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        method,
		publicKeyFile: publicKeyFile,
		decoder:       decoder{validationOpts: validationOpts},
		allowWeakKey:  allowWeakKey,
	}
}

// NewRS256Encoder creates a new RSA-SHA256 JWT encoder with a private key file.
//
// Parameters:
//   - privateKeyFile: Path to PEM-encoded RSA private key file
//
// Security: Private key files should be protected with strict file permissions (0600).
// Never commit private keys to version control or expose them in logs. Consider using
// environment variables or secure key management systems for production deployments.
// Keys with a modulus below 2048 bits are rejected; use NewRS256EncoderWithOptions
// to lift that floor for testing.
//
// Example:
//
//	encoder := cryptojwt.NewRS256Encoder("private.pem")
//	token, err := encoder.Encode(`{"user":"alice","exp":1735689600}`)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewRS256Encoder(privateKeyFile string) Encoder {
	return NewRS256EncoderWithOptions(privateKeyFile, false)
}

// NewRS256EncoderWithOptions creates a new RSA-SHA256 JWT encoder with options.
//
// Parameters:
//   - privateKeyFile: Path to PEM-encoded RSA private key file
//   - allowWeakKey: If true, allows keys shorter than 2048 bits (TESTING ONLY)
//
// Security: Setting allowWeakKey=true accepts RSA moduli that are considered
// factorable. Only use this for testing with non-production data.
func NewRS256EncoderWithOptions(privateKeyFile string, allowWeakKey bool) Encoder {
	return newRSEncoder(jwt.SigningMethodRS256, privateKeyFile, allowWeakKey)
}

// NewRS256DecoderWithPrivateKeyFile creates a new RSA-SHA256 JWT decoder with a private key file.
func NewRS256DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewRS256DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS256DecoderWithPrivateKeyFileAndValidation creates a new RSA-SHA256 JWT decoder with validation options.
func NewRS256DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return NewRS256DecoderWithPrivateKeyFileAndOptions(privateKeyFile, validationOpts, false)
}

// NewRS256DecoderWithPrivateKeyFileAndOptions creates a new RSA-SHA256 JWT decoder with
// validation options and, when allowWeakKey is true, acceptance of keys below 2048 bits
// (TESTING ONLY).
func NewRS256DecoderWithPrivateKeyFileAndOptions(
	privateKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return newRSDecoderWithPrivateKey(jwt.SigningMethodRS256, privateKeyFile, validationOpts, allowWeakKey)
}

// NewRS256DecoderWithPublicKeyFile creates a new RSA-SHA256 JWT decoder with a public key file.
//
// Parameters:
//   - publicKeyFile: Path to PEM-encoded RSA public key file
//
// Note: Public keys can be safely distributed and do not require special protection,
// unlike private keys. However, ensure you obtain public keys from trusted sources to
// prevent man-in-the-middle attacks. Keys with a modulus below 2048 bits are rejected;
// use NewRS256DecoderWithPublicKeyFileAndOptions to lift that floor for testing.
//
// Example:
//
//	decoder := cryptojwt.NewRS256DecoderWithPublicKeyFile("public.pem")
//	claims, err := decoder.Decode(token)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(claims) // {"user":"alice","exp":1735689600}
func NewRS256DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewRS256DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS256DecoderWithPublicKeyFileAndValidation creates a new RSA-SHA256 JWT decoder with validation options.
func NewRS256DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return NewRS256DecoderWithPublicKeyFileAndOptions(publicKeyFile, validationOpts, false)
}

// NewRS256DecoderWithPublicKeyFileAndOptions creates a new RSA-SHA256 JWT decoder with
// validation options and, when allowWeakKey is true, acceptance of keys below 2048 bits
// (TESTING ONLY).
func NewRS256DecoderWithPublicKeyFileAndOptions(
	publicKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return newRSDecoderWithPublicKey(jwt.SigningMethodRS256, publicKeyFile, validationOpts, allowWeakKey)
}

// NewRS384Encoder creates a new RSA-SHA384 JWT encoder with a private key file.
func NewRS384Encoder(privateKeyFile string) Encoder {
	return NewRS384EncoderWithOptions(privateKeyFile, false)
}

// NewRS384EncoderWithOptions creates a new RSA-SHA384 JWT encoder, accepting keys below
// 2048 bits when allowWeakKey is true (TESTING ONLY).
func NewRS384EncoderWithOptions(privateKeyFile string, allowWeakKey bool) Encoder {
	return newRSEncoder(jwt.SigningMethodRS384, privateKeyFile, allowWeakKey)
}

// NewRS384DecoderWithPrivateKeyFile creates a new RSA-SHA384 JWT decoder with a private key file.
func NewRS384DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewRS384DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS384DecoderWithPrivateKeyFileAndValidation creates a new RSA-SHA384 JWT decoder with validation options.
func NewRS384DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return NewRS384DecoderWithPrivateKeyFileAndOptions(privateKeyFile, validationOpts, false)
}

// NewRS384DecoderWithPrivateKeyFileAndOptions creates a new RSA-SHA384 JWT decoder with
// validation options and, when allowWeakKey is true, acceptance of keys below 2048 bits
// (TESTING ONLY).
func NewRS384DecoderWithPrivateKeyFileAndOptions(
	privateKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return newRSDecoderWithPrivateKey(jwt.SigningMethodRS384, privateKeyFile, validationOpts, allowWeakKey)
}

// NewRS384DecoderWithPublicKeyFile creates a new RSA-SHA384 JWT decoder with a public key file.
func NewRS384DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewRS384DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS384DecoderWithPublicKeyFileAndValidation creates a new RSA-SHA384 JWT decoder with validation options.
func NewRS384DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return NewRS384DecoderWithPublicKeyFileAndOptions(publicKeyFile, validationOpts, false)
}

// NewRS384DecoderWithPublicKeyFileAndOptions creates a new RSA-SHA384 JWT decoder with
// validation options and, when allowWeakKey is true, acceptance of keys below 2048 bits
// (TESTING ONLY).
func NewRS384DecoderWithPublicKeyFileAndOptions(
	publicKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return newRSDecoderWithPublicKey(jwt.SigningMethodRS384, publicKeyFile, validationOpts, allowWeakKey)
}

// NewRS512Encoder creates a new RSA-SHA512 JWT encoder with a private key file.
func NewRS512Encoder(privateKeyFile string) Encoder {
	return NewRS512EncoderWithOptions(privateKeyFile, false)
}

// NewRS512EncoderWithOptions creates a new RSA-SHA512 JWT encoder, accepting keys below
// 2048 bits when allowWeakKey is true (TESTING ONLY).
func NewRS512EncoderWithOptions(privateKeyFile string, allowWeakKey bool) Encoder {
	return newRSEncoder(jwt.SigningMethodRS512, privateKeyFile, allowWeakKey)
}

// NewRS512DecoderWithPrivateKeyFile creates a new RSA-SHA512 JWT decoder with a private key file.
func NewRS512DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewRS512DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS512DecoderWithPrivateKeyFileAndValidation creates a new RSA-SHA512 JWT decoder with validation options.
func NewRS512DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return NewRS512DecoderWithPrivateKeyFileAndOptions(privateKeyFile, validationOpts, false)
}

// NewRS512DecoderWithPrivateKeyFileAndOptions creates a new RSA-SHA512 JWT decoder with
// validation options and, when allowWeakKey is true, acceptance of keys below 2048 bits
// (TESTING ONLY).
func NewRS512DecoderWithPrivateKeyFileAndOptions(
	privateKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return newRSDecoderWithPrivateKey(jwt.SigningMethodRS512, privateKeyFile, validationOpts, allowWeakKey)
}

// NewRS512DecoderWithPublicKeyFile creates a new RSA-SHA512 JWT decoder with a public key file.
func NewRS512DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewRS512DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS512DecoderWithPublicKeyFileAndValidation creates a new RSA-SHA512 JWT decoder with validation options.
func NewRS512DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return NewRS512DecoderWithPublicKeyFileAndOptions(publicKeyFile, validationOpts, false)
}

// NewRS512DecoderWithPublicKeyFileAndOptions creates a new RSA-SHA512 JWT decoder with
// validation options and, when allowWeakKey is true, acceptance of keys below 2048 bits
// (TESTING ONLY).
func NewRS512DecoderWithPublicKeyFileAndOptions(
	publicKeyFile string, validationOpts ValidationOptions, allowWeakKey bool,
) Decoder {
	return newRSDecoderWithPublicKey(jwt.SigningMethodRS512, publicKeyFile, validationOpts, allowWeakKey)
}

// validateRSAKeySize rejects a modulus below minRSAKeyBits unless the caller opted out.
// jwt.ParseRSAPrivateKeyFromPEM and ParseRSAPublicKeyFromPEM validate PEM structure
// only, so the strength check has to happen here.
func validateRSAKeySize(modulusBits int, allowWeakKey bool) error {
	if allowWeakKey || modulusBits >= minRSAKeyBits {
		return nil
	}
	return fmt.Errorf(
		"%w: RSA key is %d bits, minimum %d required. Use --allow-weak-key flag to bypass this check for testing purposes only",
		ErrWeakKey, modulusBits, minRSAKeyBits)
}

func readPrivateRSAKey(privateKeyFile string, allowWeakKey bool) (crypto.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := keyfile.Read(privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: error reading private key file: %w", ErrInvalidKey, err)
	}
	rsaPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: error parsing RSA private key: %w", ErrInvalidKey, err)
	}
	if err := validateRSAKeySize(rsaPrivateKey.N.BitLen(), allowWeakKey); err != nil {
		return nil, nil, err
	}
	publicKey := rsaPrivateKey.Public()
	return rsaPrivateKey, publicKey, nil
}

func readPublicRSAKey(publicKeyFile string, allowWeakKey bool) (*rsa.PublicKey, error) {
	publicKey, err := keyfile.Read(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: error reading public key file: %w", ErrInvalidKey, err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: error parsing RSA public key: %w", ErrInvalidKey, err)
	}
	if err := validateRSAKeySize(key.N.BitLen(), allowWeakKey); err != nil {
		return nil, err
	}
	return key, nil
}

func (j *rsjwtEncoderWithPrivateKeyFile) Encode(payload string) (string, error) {
	privateKey, _, err := readPrivateRSAKey(j.privateKeyFile, j.allowWeakKey)
	if err != nil {
		return "", err
	}
	return j.encoder.EncodeJWT(privateKey, j.method, payload)
}

func (j *rsjwtDecoderWithPrivateKeyFile) Decode(token string) (string, error) {
	_, publicKey, err := readPrivateRSAKey(j.privateKeyFile, j.allowWeakKey)
	if err != nil {
		return "", err
	}
	return j.decoder.DecodeJWT(publicKey, j.method, token)
}

func (j *rsjwtDecoderWithPublicKeyFile) Decode(token string) (string, error) {
	key, err := readPublicRSAKey(j.publicKeyFile, j.allowWeakKey)
	if err != nil {
		return "", err
	}
	return j.decoder.DecodeJWT(key, j.method, token)
}
