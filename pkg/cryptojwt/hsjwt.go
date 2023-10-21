package cryptojwt

import (
	"github.com/golang-jwt/jwt/v5"
)

type hsjwtEncoderDecoder struct {
	encoder
	decoder
	secret []byte
	method jwt.SigningMethod
}

func NewHS256Encoder(secret []byte) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method: jwt.SigningMethodHS256,
		secret: secret,
	}
}

func NewHS256Decoder(secret []byte) EncoderDecoder {
	return NewHS256Encoder(secret)
}

func NewHS384Encoder(secret []byte) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method: jwt.SigningMethodHS256,
		secret: secret,
	}
}

func NewHS384Decoder(secret []byte) EncoderDecoder {
	return NewHS384Encoder(secret)
}

func NewHS512Encoder(secret []byte) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method: jwt.SigningMethodHS256,
		secret: secret,
	}
}

func NewHS512Decoder(secret []byte) EncoderDecoder {
	return NewHS512Encoder(secret)
}

func (j *hsjwtEncoderDecoder) Decode(token string) (string, error) {
	return j.DecodeJWT(j.secret, token)
}

func (j *hsjwtEncoderDecoder) Encode(payload string) (string, error) {
	return j.EncodeJWT(j.secret, j.method, payload)
}
