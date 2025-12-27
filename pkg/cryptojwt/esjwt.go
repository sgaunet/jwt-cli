package cryptojwt

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type esjwtEncoderWithPrivateKeyFile struct {
	encoder encoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type esjwtEncoderWithCachedPrivateKey struct {
	encoder    encoder
	privateKey crypto.PrivateKey
	method     jwt.SigningMethod
}

type esjwtDecoderWithPrivateKeyFile struct {
	decoder decoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type esjwtDecoderWithPublicKeyFile struct {
	decoder decoder
	publicKeyFile string
	method        jwt.SigningMethod
}

type esjwtDecoderWithCachedPublicKey struct {
	decoder   decoder
	publicKey crypto.PublicKey
	method    jwt.SigningMethod
}

// NewES256Encoder creates a new ECDSA-SHA256 JWT encoder with a private key file.
//
// Parameters:
//   - privateKeyFile: Path to PEM-encoded ECDSA private key file (P-256 curve)
//
// Security: Private key files should be protected with strict file permissions (0600).
// Never commit private keys to version control. ECDSA keys are typically smaller than
// RSA keys while providing equivalent security (256-bit ECDSA ≈ 3072-bit RSA).
//
// Example:
//
//	encoder := cryptojwt.NewES256Encoder("ec-private.pem")
//	token, err := encoder.Encode(`{"user":"alice","exp":1735689600}`)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewES256Encoder(privateKeyFile string) Encoder {
	return &esjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES256,
		privateKeyFile: privateKeyFile,
	}
}

// NewES384Encoder creates a new ECDSA-SHA384 JWT encoder with a private key file.
func NewES384Encoder(privateKeyFile string) Encoder {
	return &esjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES384,
		privateKeyFile: privateKeyFile,
	}
}

// NewES512Encoder creates a new ECDSA-SHA512 JWT encoder with a private key file.
func NewES512Encoder(privateKeyFile string) Encoder {
	return &esjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES512,
		privateKeyFile: privateKeyFile,
	}
}

// NewES256DecoderWithPrivateKeyFile creates a new ECDSA-SHA256 JWT decoder with a private key file.
func NewES256DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewES256DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewES256DecoderWithPrivateKeyFileAndValidation creates a new ECDSA-SHA256 JWT decoder with validation options.
func NewES256DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES256,
		privateKeyFile: privateKeyFile,
		decoder:        decoder{validationOpts: validationOpts},
	}
}

// NewES384DecoderWithPrivateKeyFile creates a new ECDSA-SHA384 JWT decoder with a private key file.
func NewES384DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewES384DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewES384DecoderWithPrivateKeyFileAndValidation creates a new ECDSA-SHA384 JWT decoder with validation options.
func NewES384DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES384,
		privateKeyFile: privateKeyFile,
		decoder:        decoder{validationOpts: validationOpts},
	}
}

// NewES512DecoderWithPrivateKeyFile creates a new ECDSA-SHA512 JWT decoder with a private key file.
func NewES512DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return NewES512DecoderWithPrivateKeyFileAndValidation(privateKeyFile, ValidationOptions{})
}

// NewES512DecoderWithPrivateKeyFileAndValidation creates a new ECDSA-SHA512 JWT decoder with validation options.
func NewES512DecoderWithPrivateKeyFileAndValidation(privateKeyFile string, validationOpts ValidationOptions) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES512,
		privateKeyFile: privateKeyFile,
		decoder:        decoder{validationOpts: validationOpts},
	}
}

// NewES256DecoderWithPublicKeyFile creates a new ECDSA-SHA256 JWT decoder with a public key file.
//
// Parameters:
//   - publicKeyFile: Path to PEM-encoded ECDSA public key file (P-256 curve)
//
// Note: Public keys can be safely distributed. Ensure you obtain public keys from
// trusted sources to prevent signature validation bypasses.
//
// Example:
//
//	decoder := cryptojwt.NewES256DecoderWithPublicKeyFile("ec-public.pem")
//	claims, err := decoder.Decode(token)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(claims) // {"user":"alice","exp":1735689600}
func NewES256DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewES256DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewES256DecoderWithPublicKeyFileAndValidation creates a new ECDSA-SHA256 JWT decoder with validation options.
func NewES256DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES256,
		publicKeyFile: publicKeyFile,
		decoder:       decoder{validationOpts: validationOpts},
	}
}

// NewES256EncoderWithCache creates a new ECDSA-SHA256 JWT encoder with cached private key.
//
// The private key is loaded once at creation time, improving performance for repeated
// operations. This is recommended for high-throughput scenarios.
//
// Security: The cached key remains in memory for the lifetime of the encoder. Private
// key files should have strict file permissions (0600).
//
// Performance: Eliminates repeated file reads and key parsing for encoding many tokens.
//
// Example:
//
//	encoder, err := cryptojwt.NewES256EncoderWithCache("ec-private.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for i := 0; i < 1000; i++ {
//	    token, _ := encoder.Encode(fmt.Sprintf(`{"id":%d}`, i))
//	    fmt.Println(token)
//	}
func NewES256EncoderWithCache(privateKeyFile string) (Encoder, error) {
	privateKey, _, err := readECDSAPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &esjwtEncoderWithCachedPrivateKey{
		method:     jwt.SigningMethodES256,
		privateKey: privateKey,
	}, nil
}

// NewES256DecoderWithPrivateKeyFileAndCache creates a new ECDSA-SHA256 JWT decoder with cached public key from private key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewES256DecoderWithPrivateKeyFileAndCache(privateKeyFile string) (Decoder, error) {
	return NewES256DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile, ValidationOptions{})
}

// NewES256DecoderWithPrivateKeyFileAndCacheAndValidation creates a new ECDSA-SHA256 JWT decoder with cached public key and validation options.
func NewES256DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	_, publicKey, err := readECDSAPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &esjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodES256,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewES256DecoderWithPublicKeyFileAndCache creates a new ECDSA-SHA256 JWT decoder with cached public key from public key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewES256DecoderWithPublicKeyFileAndCache(publicKeyFile string) (Decoder, error) {
	return NewES256DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile, ValidationOptions{})
}

// NewES256DecoderWithPublicKeyFileAndCacheAndValidation creates a new ECDSA-SHA256 JWT decoder with cached public key and validation options.
func NewES256DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	publicKeyBytes, err := os.ReadFile(publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}
	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing EC public key: %w", err)
	}
	return &esjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodES256,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewES384DecoderWithPublicKeyFile creates a new ECDSA-SHA384 JWT decoder with a public key file.
func NewES384DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewES384DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewES384DecoderWithPublicKeyFileAndValidation creates a new ECDSA-SHA384 JWT decoder with validation options.
func NewES384DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES384,
		publicKeyFile: publicKeyFile,
		decoder:       decoder{validationOpts: validationOpts},
	}
}

// NewES384EncoderWithCache creates a new ECDSA-SHA384 JWT encoder with cached private key.
// The private key is loaded once at creation time, improving performance for repeated operations.
func NewES384EncoderWithCache(privateKeyFile string) (Encoder, error) {
	privateKey, _, err := readECDSAPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &esjwtEncoderWithCachedPrivateKey{
		method:     jwt.SigningMethodES384,
		privateKey: privateKey,
	}, nil
}

// NewES384DecoderWithPrivateKeyFileAndCache creates a new ECDSA-SHA384 JWT decoder with cached public key from private key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewES384DecoderWithPrivateKeyFileAndCache(privateKeyFile string) (Decoder, error) {
	return NewES384DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile, ValidationOptions{})
}

// NewES384DecoderWithPrivateKeyFileAndCacheAndValidation creates a new ECDSA-SHA384 JWT decoder with cached public key and validation options.
func NewES384DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	_, publicKey, err := readECDSAPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &esjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodES384,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewES384DecoderWithPublicKeyFileAndCache creates a new ECDSA-SHA384 JWT decoder with cached public key from public key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewES384DecoderWithPublicKeyFileAndCache(publicKeyFile string) (Decoder, error) {
	return NewES384DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile, ValidationOptions{})
}

// NewES384DecoderWithPublicKeyFileAndCacheAndValidation creates a new ECDSA-SHA384 JWT decoder with cached public key and validation options.
func NewES384DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	publicKeyBytes, err := os.ReadFile(publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}
	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing EC public key: %w", err)
	}
	return &esjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodES384,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewES512DecoderWithPublicKeyFile creates a new ECDSA-SHA512 JWT decoder with a public key file.
func NewES512DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return NewES512DecoderWithPublicKeyFileAndValidation(publicKeyFile, ValidationOptions{})
}

// NewES512DecoderWithPublicKeyFileAndValidation creates a new ECDSA-SHA512 JWT decoder with validation options.
func NewES512DecoderWithPublicKeyFileAndValidation(publicKeyFile string, validationOpts ValidationOptions) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES512,
		publicKeyFile: publicKeyFile,
		decoder:       decoder{validationOpts: validationOpts},
	}
}

// NewES512EncoderWithCache creates a new ECDSA-SHA512 JWT encoder with cached private key.
// The private key is loaded once at creation time, improving performance for repeated operations.
func NewES512EncoderWithCache(privateKeyFile string) (Encoder, error) {
	privateKey, _, err := readECDSAPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &esjwtEncoderWithCachedPrivateKey{
		method:     jwt.SigningMethodES512,
		privateKey: privateKey,
	}, nil
}

// NewES512DecoderWithPrivateKeyFileAndCache creates a new ECDSA-SHA512 JWT decoder with cached public key from private key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewES512DecoderWithPrivateKeyFileAndCache(privateKeyFile string) (Decoder, error) {
	return NewES512DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile, ValidationOptions{})
}

// NewES512DecoderWithPrivateKeyFileAndCacheAndValidation creates a new ECDSA-SHA512 JWT decoder with cached public key and validation options.
func NewES512DecoderWithPrivateKeyFileAndCacheAndValidation(privateKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	_, publicKey, err := readECDSAPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return &esjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodES512,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

// NewES512DecoderWithPublicKeyFileAndCache creates a new ECDSA-SHA512 JWT decoder with cached public key from public key file.
// The key is loaded once at creation time, improving performance for repeated operations.
func NewES512DecoderWithPublicKeyFileAndCache(publicKeyFile string) (Decoder, error) {
	return NewES512DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile, ValidationOptions{})
}

// NewES512DecoderWithPublicKeyFileAndCacheAndValidation creates a new ECDSA-SHA512 JWT decoder with cached public key and validation options.
func NewES512DecoderWithPublicKeyFileAndCacheAndValidation(publicKeyFile string, validationOpts ValidationOptions) (Decoder, error) {
	publicKeyBytes, err := os.ReadFile(publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}
	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing EC public key: %w", err)
	}
	return &esjwtDecoderWithCachedPublicKey{
		method:    jwt.SigningMethodES512,
		publicKey: publicKey,
		decoder:   decoder{validationOpts: validationOpts},
	}, nil
}

func readECDSAPrivateKey(privateKeyFile string) (crypto.PrivateKey, crypto.PublicKey, error) {
	contentKeyFile, err := os.ReadFile(privateKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return nil, nil, fmt.Errorf("error reading private key file: %w", err)
	}
	block, _ := pem.Decode(contentKeyFile)
	if block == nil {
		return nil, nil, errors.New("unable to load key: PEM block is nil")
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, nil, fmt.Errorf("wrong type of key - expected EC PRIVATE KEY, got %s", block.Type)
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing EC private key: %w", err)
	}
	publicKey := privateKey.Public()
	return privateKey, publicKey, nil
}

func (j *esjwtEncoderWithPrivateKeyFile) Encode(payload string) (string, error) {
	privateKey, _, err := readECDSAPrivateKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.encoder.EncodeJWT(privateKey, j.method, payload)
}

func (j *esjwtDecoderWithPrivateKeyFile) Decode(token string) (string, error) {
	_, publicKey, err := readECDSAPrivateKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.decoder.DecodeJWT(publicKey, token)
}

func (j *esjwtDecoderWithPublicKeyFile) Decode(token string) (string, error) {
	publicKey, err := os.ReadFile(j.publicKeyFile) // #nosec G304 -- user-provided file path
	if err != nil {
		return "", fmt.Errorf("error reading public key file: %w", err)
	}
	key, err := jwt.ParseECPublicKeyFromPEM(publicKey)
	if err != nil {
		return "", fmt.Errorf("error parsing EC public key: %w", err)
	}
	return j.decoder.DecodeJWT(key, token)
}

func (j *esjwtEncoderWithCachedPrivateKey) Encode(payload string) (string, error) {
	return j.encoder.EncodeJWT(j.privateKey, j.method, payload)
}

func (j *esjwtDecoderWithCachedPublicKey) Decode(token string) (string, error) {
	return j.decoder.DecodeJWT(j.publicKey, token)
}
