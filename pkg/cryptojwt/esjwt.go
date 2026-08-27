package cryptojwt

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sgaunet/jwt-cli/internal/keyfile"
)

type esjwtEncoderWithPrivateKeyFile struct {
	encoder        encoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type esjwtDecoderWithPrivateKeyFile struct {
	decoder        decoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type esjwtDecoderWithPublicKeyFile struct {
	decoder       decoder
	publicKeyFile string
	method        jwt.SigningMethod
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

func readECDSAPrivateKey(privateKeyFile string) (crypto.PrivateKey, crypto.PublicKey, error) {
	contentKeyFile, err := keyfile.Read(privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: error reading private key file: %w", ErrInvalidKey, err)
	}
	// Before the block-type check below: a legacy OpenSSL-encrypted EC key keeps
	// the ordinary "EC PRIVATE KEY" type and carries Proc-Type/DEK-Info headers,
	// so it passes that check and fails inside x509 with a raw ASN.1 error.
	if err := checkKeyNotEncrypted(contentKeyFile); err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(contentKeyFile)
	if block == nil {
		return nil, nil, fmt.Errorf("%w: unable to load key: PEM block is nil", ErrInvalidKey)
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, nil, fmt.Errorf("%w: wrong type of key - expected EC PRIVATE KEY, got %s", ErrInvalidKey, block.Type)
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: error parsing EC private key: %w", ErrInvalidKey, err)
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
	return j.decoder.DecodeJWT(publicKey, j.method, token)
}

func (j *esjwtDecoderWithPublicKeyFile) Decode(token string) (string, error) {
	publicKey, err := keyfile.Read(j.publicKeyFile)
	if err != nil {
		return "", fmt.Errorf("%w: error reading public key file: %w", ErrInvalidKey, err)
	}
	if err := checkKeyNotEncrypted(publicKey); err != nil {
		return "", err
	}
	key, err := jwt.ParseECPublicKeyFromPEM(publicKey)
	if err != nil {
		return "", fmt.Errorf("%w: error parsing EC public key: %w", ErrInvalidKey, err)
	}
	return j.decoder.DecodeJWT(key, j.method, token)
}
