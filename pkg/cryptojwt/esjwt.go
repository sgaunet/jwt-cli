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
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES256,
		privateKeyFile: privateKeyFile,
	}
}

// NewES384DecoderWithPrivateKeyFile creates a new ECDSA-SHA384 JWT decoder with a private key file.
func NewES384DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES384,
		privateKeyFile: privateKeyFile,
	}
}

// NewES512DecoderWithPrivateKeyFile creates a new ECDSA-SHA512 JWT decoder with a private key file.
func NewES512DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES512,
		privateKeyFile: privateKeyFile,
	}
}

// NewES256DecoderWithPublicKeyFile creates a new ECDSA-SHA256 JWT decoder with a public key file.
func NewES256DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES256,
		publicKeyFile: publicKeyFile,
	}
}

// NewES384DecoderWithPublicKeyFile creates a new ECDSA-SHA384 JWT decoder with a public key file.
func NewES384DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES384,
		publicKeyFile: publicKeyFile,
	}
}

// NewES512DecoderWithPublicKeyFile creates a new ECDSA-SHA512 JWT decoder with a public key file.
func NewES512DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES512,
		publicKeyFile: publicKeyFile,
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
