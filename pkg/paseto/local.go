package paseto

import (
	"encoding/hex"
	"fmt"

	"aidanwoods.dev/go-paseto"
)

// decodeSymmetricKey decodes a hex-encoded symmetric key.
func decodeSymmetricKey(keyHex string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	return keyBytes, nil
}

// LocalV4Encoder encodes and decodes PASETO V4 local (symmetric) tokens.
type LocalV4Encoder struct {
	validator

	key paseto.V4SymmetricKey
}

// NewLocalV4Encoder creates a PASETO V4 local encoder/decoder from a
// hex-encoded 32-byte symmetric key.
func NewLocalV4Encoder(keyHex string, opts ...Option) (*LocalV4Encoder, error) {
	keyBytes, err := decodeSymmetricKey(keyHex)
	if err != nil {
		return nil, err
	}

	key, err := paseto.V4SymmetricKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &LocalV4Encoder{
		key:       key,
		validator: newValidator(opts),
	}, nil
}

// Encode encrypts the JSON payload into a v4.local token.
func (l *LocalV4Encoder) Encode(payload string) (string, error) {
	token, err := newTokenFromPayload(payload)
	if err != nil {
		return "", err
	}
	return token.V4Encrypt(l.key, nil), nil
}

// DecodeWithFooter decrypts a v4.local token and returns its claims as
// indented JSON, along with the token's authenticated footer.
//
// The token's authentication tag is verified. Claims are validated only when
// the encoder was built WithValidation; by default an expired token decodes
// successfully.
func (l *LocalV4Encoder) DecodeWithFooter(tokenString string) (DecodedToken, error) {
	parser := l.parser()
	token, err := parser.ParseV4Local(l.key, tokenString, nil)
	if err != nil {
		return DecodedToken{}, wrapDecodeError(err)
	}
	return decodeResult(token)
}

// Decode verifies the token and returns its claims as indented JSON,
// discarding any footer. Use DecodeWithFooter to see the footer too.
func (l *LocalV4Encoder) Decode(tokenString string) (string, error) {
	decoded, err := l.DecodeWithFooter(tokenString)
	return decoded.Claims, err
}

// LocalV3Encoder encodes and decodes PASETO V3 local (symmetric) tokens.
type LocalV3Encoder struct {
	validator

	key paseto.V3SymmetricKey
}

// NewLocalV3Encoder creates a PASETO V3 local encoder/decoder from a
// hex-encoded 32-byte symmetric key.
func NewLocalV3Encoder(keyHex string, opts ...Option) (*LocalV3Encoder, error) {
	keyBytes, err := decodeSymmetricKey(keyHex)
	if err != nil {
		return nil, err
	}

	key, err := paseto.V3SymmetricKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &LocalV3Encoder{
		key:       key,
		validator: newValidator(opts),
	}, nil
}

// Encode encrypts the JSON payload into a v3.local token.
func (l *LocalV3Encoder) Encode(payload string) (string, error) {
	token, err := newTokenFromPayload(payload)
	if err != nil {
		return "", err
	}
	return token.V3Encrypt(l.key, nil), nil
}

// DecodeWithFooter decrypts a v3.local token and returns its claims as
// indented JSON, along with the token's authenticated footer.
//
// The token's authentication tag is verified. Claims are validated only when
// the encoder was built WithValidation; by default an expired token decodes
// successfully.
func (l *LocalV3Encoder) DecodeWithFooter(tokenString string) (DecodedToken, error) {
	parser := l.parser()
	token, err := parser.ParseV3Local(l.key, tokenString, nil)
	if err != nil {
		return DecodedToken{}, wrapDecodeError(err)
	}
	return decodeResult(token)
}

// Decode verifies the token and returns its claims as indented JSON,
// discarding any footer. Use DecodeWithFooter to see the footer too.
func (l *LocalV3Encoder) Decode(tokenString string) (string, error) {
	decoded, err := l.DecodeWithFooter(tokenString)
	return decoded.Claims, err
}

// LocalV2Encoder encodes and decodes PASETO V2 local (symmetric) tokens.
type LocalV2Encoder struct {
	validator

	key paseto.V2SymmetricKey
}

// NewLocalV2Encoder creates a PASETO V2 local encoder/decoder from a
// hex-encoded 32-byte symmetric key.
func NewLocalV2Encoder(keyHex string, opts ...Option) (*LocalV2Encoder, error) {
	keyBytes, err := decodeSymmetricKey(keyHex)
	if err != nil {
		return nil, err
	}

	key, err := paseto.V2SymmetricKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &LocalV2Encoder{
		key:       key,
		validator: newValidator(opts),
	}, nil
}

// Encode encrypts the JSON payload into a v2.local token.
func (l *LocalV2Encoder) Encode(payload string) (string, error) {
	token, err := newTokenFromPayload(payload)
	if err != nil {
		return "", err
	}
	// PASETO V2 has no implicit assertion parameter.
	return token.V2Encrypt(l.key), nil
}

// DecodeWithFooter decrypts a v2.local token and returns its claims as
// indented JSON, along with the token's authenticated footer.
//
// The token's authentication tag is verified. Claims are validated only when
// the encoder was built WithValidation; by default an expired token decodes
// successfully.
func (l *LocalV2Encoder) DecodeWithFooter(tokenString string) (DecodedToken, error) {
	parser := l.parser()
	token, err := parser.ParseV2Local(l.key, tokenString)
	if err != nil {
		return DecodedToken{}, wrapDecodeError(err)
	}
	return decodeResult(token)
}

// Decode verifies the token and returns its claims as indented JSON,
// discarding any footer. Use DecodeWithFooter to see the footer too.
func (l *LocalV2Encoder) Decode(tokenString string) (string, error) {
	decoded, err := l.DecodeWithFooter(tokenString)
	return decoded.Claims, err
}
