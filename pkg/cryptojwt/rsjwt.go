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

// NewRS256Encoder creates a new RSA-SHA256 JWT encoder with a private key file.
func NewRS256Encoder(privateKeyFile string) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS256,
		privateKeyFile: privateKeyFile,
	}
}

// NewRS256DecoderWithPrivateKeyFile creates a new RSA-SHA256 JWT decoder with a private key file.
func NewRS256DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS256,
		privateKeyFile: privateKeyFile,
	}
}

// NewRS256DecoderWithPublicKeyFile creates a new RSA-SHA256 JWT decoder with a public key file.
func NewRS256DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS256,
		publicKeyFile: publicKeyFile,
	}
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
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS384,
		privateKeyFile: privateKeyFile,
	}
}

// NewRS384DecoderWithPublicKeyFile creates a new RSA-SHA384 JWT decoder with a public key file.
func NewRS384DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS384,
		publicKeyFile: publicKeyFile,
	}
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
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS512,
		privateKeyFile: privateKeyFile,
	}
}

// NewRS512DecoderWithPublicKeyFile creates a new RSA-SHA512 JWT decoder with a public key file.
func NewRS512DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS512,
		publicKeyFile: publicKeyFile,
	}
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
