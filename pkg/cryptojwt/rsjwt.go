package cryptojwt

import (
	"crypto"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

type rsjwtEncoderWithPrivateKeyFile struct {
	encoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type rsjwtDecoderWithPrivateKeyFile struct {
	decoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type rsjwtDecoderWithPublicKeyFile struct {
	decoder
	publicKeyFile string
	method        jwt.SigningMethod
}

func NewRS256Encoder(privateKeyFile string) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS256,
		privateKeyFile: privateKeyFile,
	}
}

func NewRS256DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS256,
		privateKeyFile: privateKeyFile,
	}
}

func NewRS256DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS256,
		publicKeyFile: publicKeyFile,
	}
}

func NewRS384Encoder(privateKeyFile string) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS384,
		privateKeyFile: privateKeyFile,
	}
}

func NewRS384DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS384,
		privateKeyFile: privateKeyFile,
	}
}

func NewRS384DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS384,
		publicKeyFile: publicKeyFile,
	}
}

func NewRS512Encoder(privateKeyFile string) Encoder {
	return &rsjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS512,
		privateKeyFile: privateKeyFile,
	}
}

func NewRS512DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &rsjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodRS512,
		privateKeyFile: privateKeyFile,
	}
}

func NewRS512DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &rsjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodRS512,
		publicKeyFile: publicKeyFile,
	}
}

func readPrivateRSAKey(privateKeyFile string) (crypto.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading private key file: %v", err)
	}
	rsaPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing RSA private key: %v", err)
	}
	publicKey := rsaPrivateKey.Public()
	return rsaPrivateKey, publicKey, nil
}

func (j *rsjwtEncoderWithPrivateKeyFile) Encode(payload string) (string, error) {
	privateKey, _, err := readPrivateRSAKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.EncodeJWT(privateKey, j.method, payload)
}

func (j *rsjwtDecoderWithPrivateKeyFile) Decode(token string) (string, error) {
	_, publicKey, err := readPrivateRSAKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.DecodeJWT(publicKey, token)
}

func (j *rsjwtDecoderWithPublicKeyFile) Decode(token string) (string, error) {
	publicKey, err := os.ReadFile(j.publicKeyFile)
	if err != nil {
		return "", fmt.Errorf("error reading public key file: %v", err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return "", fmt.Errorf("error parsing RSA public key: %v", err)
	}
	return j.DecodeJWT(key, token)
}
