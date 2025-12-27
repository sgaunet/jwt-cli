package cryptojwt

import (
	"crypto"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type rsjwtEncoderWithPrivateKeyFile struct {
	encoder encoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type rsjwtEncoderWithCachedPrivateKey struct {
	encoder    encoder
	privateKey crypto.PrivateKey
	method     jwt.SigningMethod
}

type rsjwtDecoderWithPrivateKeyFile struct {
	decoder decoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type rsjwtDecoderWithPublicKeyFile struct {
	decoder decoder
	publicKeyFile string
	method        jwt.SigningMethod
}

type rsjwtDecoderWithCachedPublicKey struct {
	decoder   decoder
	publicKey crypto.PublicKey
	method    jwt.SigningMethod
}

// NewRS256Encoder creates a new RSA-SHA256 JWT encoder with a private key file.
//
// Parameters:
//   - privateKeyFile: Path to PEM-encoded RSA private key file
//
// Security: Private key files should be protected with strict file permissions (0600).
// Never commit private keys to version control or expose them in logs. Consider using
// environment variables or secure key management systems for production deployments.
//
// Example:
//
//	encoder := cryptojwt.NewRS256Encoder("private.pem")
//	token, err := encoder.Encode(`{"user":"alice","exp":1735689600}`)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewRS256Encoder(privateKeyFile string) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS256,
		privateKeyFile: privateKeyFile,
	}
}

// NewRS256DecoderWithPrivateKeyFile creates a new RSA-SHA256 JWT decoder with a private key file.
func NewRS256DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewRS256DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS256DecoderWithPrivateKeyFileAndValidation creates a new RSA-SHA256 JWT decoder with validation options.
func NewRS256DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS256,
		privateKeyFile: privateKeyFile,
		decoder:        decoder{validationOpts: validationOpts},
	}
}

// NewRS256DecoderWithPublicKeyFile creates a new RSA-SHA256 JWT decoder with a public key file.
//
// Parameters:
//   - publicKeyFile: Path to PEM-encoded RSA public key file
//
// Note: Public keys can be safely distributed and do not require special protection,
// unlike private keys. However, ensure you obtain public keys from trusted sources to
// prevent man-in-the-middle attacks.
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
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS256,
		publicKeyFile: publicKeyFile,
		decoder:       decoder{validationOpts: validationOpts},
	}
}

// NewRS256EncoderWithCache creates a new RSA-SHA256 JWT encoder with cached private key.
//
// The private key is loaded once at creation time, improving performance for repeated
// operations. This is recommended for high-throughput scenarios where you need to encode
// many tokens without repeated file I/O.
//
// Security: The cached key remains in memory for the lifetime of the encoder. Ensure
// proper memory protection in production environments. Private key files should have
// strict file permissions (0600).
//
// Performance: For applications encoding thousands of tokens, this can provide significant
// performance improvements by eliminating repeated file reads and key parsing.
//
// Example:
//
//	encoder, err := cryptojwt.NewRS256EncoderWithCache("private.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Encode many tokens efficiently
//	for i := 0; i < 1000; i++ {
//	    token, _ := encoder.Encode(fmt.Sprintf(`{"id":%d}`, i))
//	    fmt.Println(token)
//	}
func NewRS256EncoderWithCache(privateKeyFile string) (Encoder, error) {
	privateKey, _, err := readPrivateRSAKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &rsjwtEncoderWithCachedPrivateKey{
		method:     jwt.SigningMethodRS256,
		privateKey: privateKey,
	}, nil
}

// NewRS256DecoderWithPrivateKeyFileAndCache creates a new RSA-SHA256 JWT decoder with cached public key from private key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewRS256DecoderWithPrivateKeyFileAndCache(privateKeyFile string) (Decoder, error) {
	return NewRS256DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS256DecoderWithPrivateKeyFileAndCacheAndValidation creates a new RSA-SHA256 JWT decoder with cached public key and validation options.
func NewRS256DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	_, publicKey, err := readPrivateRSAKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &rsjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodRS256,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewRS256DecoderWithPublicKeyFileAndCache creates a new RSA-SHA256 JWT decoder with cached public key from public key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewRS256DecoderWithPublicKeyFileAndCache(publicKeyFile string) (Decoder, error) {
	return NewRS256DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS256DecoderWithPublicKeyFileAndCacheAndValidation creates a new RSA-SHA256 JWT decoder with cached public key and validation options.
func NewRS256DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	publicKeyBytes, err := os.ReadFile(publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA public key: %w", err)
	}
	return &rsjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodRS256,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewRS384Encoder creates a new RSA-SHA384 JWT encoder with a private key file.
func NewRS384Encoder(privateKeyFile string) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS384,
		privateKeyFile: privateKeyFile,
	}
}

// NewRS384DecoderWithPrivateKeyFile creates a new RSA-SHA384 JWT decoder with a private key file.
func NewRS384DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewRS384DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS384DecoderWithPrivateKeyFileAndValidation creates a new RSA-SHA384 JWT decoder with validation options.
func NewRS384DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS384,
		privateKeyFile: privateKeyFile,
		decoder:        decoder{validationOpts: validationOpts},
	}
}

// NewRS384DecoderWithPublicKeyFile creates a new RSA-SHA384 JWT decoder with a public key file.
func NewRS384DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewRS384DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS384DecoderWithPublicKeyFileAndValidation creates a new RSA-SHA384 JWT decoder with validation options.
func NewRS384DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS384,
		publicKeyFile: publicKeyFile,
		decoder:       decoder{validationOpts: validationOpts},
	}
}

// NewRS384EncoderWithCache creates a new RSA-SHA384 JWT encoder with cached private key.
// The private key is loaded once at creation time, improving performance for repeated operations.
func NewRS384EncoderWithCache(privateKeyFile string) (Encoder, error) {
	privateKey, _, err := readPrivateRSAKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &rsjwtEncoderWithCachedPrivateKey{
		method:     jwt.SigningMethodRS384,
		privateKey: privateKey,
	}, nil
}

// NewRS384DecoderWithPrivateKeyFileAndCache creates a new RSA-SHA384 JWT decoder with cached public key from private key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewRS384DecoderWithPrivateKeyFileAndCache(privateKeyFile string) (Decoder, error) {
	return NewRS384DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS384DecoderWithPrivateKeyFileAndCacheAndValidation creates a new RSA-SHA384 JWT decoder with cached public key and validation options.
func NewRS384DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	_, publicKey, err := readPrivateRSAKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &rsjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodRS384,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewRS384DecoderWithPublicKeyFileAndCache creates a new RSA-SHA384 JWT decoder with cached public key from public key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewRS384DecoderWithPublicKeyFileAndCache(publicKeyFile string) (Decoder, error) {
	return NewRS384DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS384DecoderWithPublicKeyFileAndCacheAndValidation creates a new RSA-SHA384 JWT decoder with cached public key and validation options.
func NewRS384DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	publicKeyBytes, err := os.ReadFile(publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA public key: %w", err)
	}
	return &rsjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodRS384,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewRS512Encoder creates a new RSA-SHA512 JWT encoder with a private key file.
func NewRS512Encoder(privateKeyFile string) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS512,
		privateKeyFile: privateKeyFile,
	}
}

// NewRS512DecoderWithPrivateKeyFile creates a new RSA-SHA512 JWT decoder with a private key file.
func NewRS512DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewRS512DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS512DecoderWithPrivateKeyFileAndValidation creates a new RSA-SHA512 JWT decoder with validation options.
func NewRS512DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS512,
		privateKeyFile: privateKeyFile,
		decoder:        decoder{validationOpts: validationOpts},
	}
}

// NewRS512DecoderWithPublicKeyFile creates a new RSA-SHA512 JWT decoder with a public key file.
func NewRS512DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewRS512DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS512DecoderWithPublicKeyFileAndValidation creates a new RSA-SHA512 JWT decoder with validation options.
func NewRS512DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS512,
		publicKeyFile: publicKeyFile,
		decoder:       decoder{validationOpts: validationOpts},
	}
}

// NewRS512EncoderWithCache creates a new RSA-SHA512 JWT encoder with cached private key.
// The private key is loaded once at creation time, improving performance for repeated operations.
func NewRS512EncoderWithCache(privateKeyFile string) (Encoder, error) {
	privateKey, _, err := readPrivateRSAKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &rsjwtEncoderWithCachedPrivateKey{
		method:     jwt.SigningMethodRS512,
		privateKey: privateKey,
	}, nil
}

// NewRS512DecoderWithPrivateKeyFileAndCache creates a new RSA-SHA512 JWT decoder with cached public key from private key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewRS512DecoderWithPrivateKeyFileAndCache(privateKeyFile string) (Decoder, error) {
	return NewRS512DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile, ValidationOptions{})
}

// NewRS512DecoderWithPrivateKeyFileAndCacheAndValidation creates a new RSA-SHA512 JWT decoder with cached public key and validation options.
func NewRS512DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	_, publicKey, err := readPrivateRSAKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &rsjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodRS512,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewRS512DecoderWithPublicKeyFileAndCache creates a new RSA-SHA512 JWT decoder with cached public key from public key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewRS512DecoderWithPublicKeyFileAndCache(publicKeyFile string) (Decoder, error) {
	return NewRS512DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile, ValidationOptions{})
}

// NewRS512DecoderWithPublicKeyFileAndCacheAndValidation creates a new RSA-SHA512 JWT decoder with cached public key and validation options.
func NewRS512DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	publicKeyBytes, err := os.ReadFile(publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA public key: %w", err)
	}
	return &rsjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodRS512,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

func readPrivateRSAKey(privateKeyFile string) (crypto.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := os.ReadFile(privateKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, nil, fmt.Errorf("error reading private key file: %w", err)
	}
	rsaPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing RSA private key: %w", err)
	}
	publicKey := rsaPrivateKey.Public()
	return rsaPrivateKey, publicKey, nil
}

func (j *rsjwtEncoderWithPrivateKeyFile) Encode(payload string) (string, error) {
	privateKey, _, err := readPrivateRSAKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.encoder.EncodeJWT(privateKey, j.method, payload)
}

func (j *rsjwtDecoderWithPrivateKeyFile) Decode(token string) (string, error) {
	_, publicKey, err := readPrivateRSAKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.decoder.DecodeJWT(publicKey, token)
}

func (j *rsjwtDecoderWithPublicKeyFile) Decode(token string) (string, error) {
	publicKey, err := os.ReadFile(j.publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return "", fmt.Errorf("error reading public key file: %w", err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return "", fmt.Errorf("error parsing RSA public key: %w", err)
	}
	return j.decoder.DecodeJWT(key, token)
}

func (j *rsjwtEncoderWithCachedPrivateKey) Encode(payload string) (string, error) {
	return j.encoder.EncodeJWT(j.privateKey, j.method, payload)
}

func (j *rsjwtDecoderWithCachedPublicKey) Decode(token string) (string, error) {
	return j.decoder.DecodeJWT(j.publicKey, token)
}
