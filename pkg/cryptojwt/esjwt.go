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

// NewES256Encoder creates a new ECDSA-SHA256 JWT encoder with a private key file.
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
