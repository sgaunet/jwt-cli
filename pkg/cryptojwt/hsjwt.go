package cryptojwt

import (
	"github.com/golang-jwt/jwt/v5"
)

type hsjwtEncoderDecoder struct {
	encoder encoder
	decoder decoder
	secret []byte
	method jwt.SigningMethod
}

// NewHS256Encoder creates a new HMAC-SHA256 JWT encoder/decoder.
func NewHS256Encoder(secret []byte) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method: jwt.SigningMethodHS256,
		secret: secret,
	}
}

// NewHS256Decoder creates a new HMAC-SHA256 JWT decoder.
func NewHS256Decoder(secret []byte) EncoderDecoder {
	return NewHS256Encoder(secret)
}

// NewHS384Encoder creates a new HMAC-SHA384 JWT encoder/decoder.
func NewHS384Encoder(secret []byte) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method: jwt.SigningMethodHS384,
		secret: secret,
	}
}

// NewHS384Decoder creates a new HMAC-SHA384 JWT decoder.
func NewHS384Decoder(secret []byte) EncoderDecoder {
	return NewHS384Encoder(secret)
}

// NewHS512Encoder creates a new HMAC-SHA512 JWT encoder/decoder.
func NewHS512Encoder(secret []byte) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method: jwt.SigningMethodHS512,
		secret: secret,
	}
}

// NewHS512Decoder creates a new HMAC-SHA512 JWT decoder.
func NewHS512Decoder(secret []byte) EncoderDecoder {
	return NewHS512Encoder(secret)
}

func (j *hsjwtEncoderDecoder) Decode(token string) (string, error) {
	return j.decoder.DecodeJWT(j.secret, token)
}

func (j *hsjwtEncoderDecoder) Encode(payload string) (string, error) {
	return j.encoder.EncodeJWT(j.secret, j.method, payload)
}
