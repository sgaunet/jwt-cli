package cryptojwt

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type esjwtEncoderWithPrivateKeyFile struct {
	encoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type esjwtDecoderWithPrivateKeyFile struct {
	decoder
	privateKeyFile string
	method         jwt.SigningMethod
}

type esjwtDecoderWithPublicKeyFile struct {
	decoder
	publicKeyFile string
	method        jwt.SigningMethod
}

func NewES256Encoder(privateKeyFile string) Encoder {
	return &esjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES256,
		privateKeyFile: privateKeyFile,
	}
}

func NewES384Encoder(privateKeyFile string) Encoder {
	return &esjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES384,
		privateKeyFile: privateKeyFile,
	}
}

func NewES512Encoder(privateKeyFile string) Encoder {
	return &esjwtEncoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES512,
		privateKeyFile: privateKeyFile,
	}
}

func NewES256DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES256,
		privateKeyFile: privateKeyFile,
	}
}

func NewES384DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES384,
		privateKeyFile: privateKeyFile,
	}
}

func NewES512DecoderWithPrivateKeyFile(privateKeyFile string) Decoder {
	return &esjwtDecoderWithPrivateKeyFile{
		method:         jwt.SigningMethodES512,
		privateKeyFile: privateKeyFile,
	}
}

func NewES256DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES256,
		publicKeyFile: publicKeyFile,
	}
}

func NewES384DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES384,
		publicKeyFile: publicKeyFile,
	}
}

func NewES512DecoderWithPublicKeyFile(publicKeyFile string) Decoder {
	return &esjwtDecoderWithPublicKeyFile{
		method:        jwt.SigningMethodES512,
		publicKeyFile: publicKeyFile,
	}
}

func readECDSAPrivateKey(privateKeyFile string) (crypto.PrivateKey, crypto.PublicKey, error) {
	contentKeyFile, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading private key file: %v", err)
	}
	block, _ := pem.Decode(contentKeyFile)
	if block == nil {
		return nil, nil, fmt.Errorf("unable to load key")
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, nil, fmt.Errorf("wrong type of key - %s", block.Type)
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing EC private key: %v", err)
	}
	publicKey := privateKey.Public()
	return privateKey, publicKey, nil
}

func (j *esjwtEncoderWithPrivateKeyFile) Encode(payload string) (string, error) {
	privateKey, _, err := readECDSAPrivateKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.EncodeJWT(privateKey, j.method, payload)
}

func (j *esjwtDecoderWithPrivateKeyFile) Decode(token string) (string, error) {
	_, publicKey, err := readECDSAPrivateKey(j.privateKeyFile)
	if err != nil {
		return "", err
	}
	return j.DecodeJWT(publicKey, token)
}

func (j *esjwtDecoderWithPublicKeyFile) Decode(token string) (string, error) {
	publicKey, err := os.ReadFile(j.publicKeyFile)
	if err != nil {
		return "", fmt.Errorf("error reading public key file: %v", err)
	}
	key, err := jwt.ParseECPublicKeyFromPEM(publicKey)
	if err != nil {
		return "", fmt.Errorf("error parsing RSA public key: %v", err)
	}
	return j.DecodeJWT(key, token)
}
