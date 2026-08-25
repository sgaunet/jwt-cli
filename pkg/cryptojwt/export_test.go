package cryptojwt

import "github.com/golang-jwt/jwt/v5"

// NewHSEncoderDecoderWithMethod builds an HMAC encoder/decoder with an
// arbitrary signing method, which no exported constructor allows. It exists so
// the defensive default branch in validateSecret can be exercised from the
// black-box tests in package cryptojwt_test. Declared in a _test.go file, so it
// is absent from the package's real API surface.
func NewHSEncoderDecoderWithMethod(method jwt.SigningMethod, secret []byte) EncoderDecoder {
	return &hsjwtEncoderDecoder{
		method: method,
		secret: secret,
	}
}
