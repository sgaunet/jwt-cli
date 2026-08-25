package paseto

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"aidanwoods.dev/go-paseto"
)

// errPrivateKeyRequired reports an attempt to sign with a decoder that was
// built from a public key only.
func errPrivateKeyRequired() error {
	return fmt.Errorf("%w: private key required for encoding", ErrInvalidKey)
}

// PublicV4Encoder encodes and decodes PASETO V4 public (Ed25519) tokens.
//
// A value built from a public key can only decode; Encode reports
// ErrInvalidKey in that case.
type PublicV4Encoder struct {
	validator

	privateKey *paseto.V4AsymmetricSecretKey
	publicKey  paseto.V4AsymmetricPublicKey
}

// NewPublicV4EncoderFromPrivateKey creates a PASETO V4 public encoder/decoder
// from an Ed25519 private key file, in PKCS#8 PEM or raw form.
func NewPublicV4EncoderFromPrivateKey(privateKeyFile string, opts ...Option) (*PublicV4Encoder, error) {
	keyBytes, err := loadEd25519PrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}

	privateKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &PublicV4Encoder{
		privateKey: &privateKey,
		publicKey:  privateKey.Public(),
		validator:  newValidator(opts),
	}, nil
}

// NewPublicV4DecoderFromPublicKey creates a PASETO V4 public decoder from an
// Ed25519 public key file, in PKIX PEM or raw form.
func NewPublicV4DecoderFromPublicKey(publicKeyFile string, opts ...Option) (*PublicV4Encoder, error) {
	keyBytes, err := loadEd25519PublicKey(publicKeyFile)
	if err != nil {
		return nil, err
	}

	publicKey, err := paseto.NewV4AsymmetricPublicKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &PublicV4Encoder{
		publicKey: publicKey,
		validator: newValidator(opts),
	}, nil
}

// NewPublicV4EncoderFromHex creates a PASETO V4 public encoder/decoder from a
// hex-encoded Ed25519 private key.
func NewPublicV4EncoderFromHex(privateKeyHex string, opts ...Option) (*PublicV4Encoder, error) {
	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: key must be %d bytes", ErrInvalidKey, ed25519.PrivateKeySize)
	}

	privateKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &PublicV4Encoder{
		privateKey: &privateKey,
		publicKey:  privateKey.Public(),
		validator:  newValidator(opts),
	}, nil
}

// Encode signs the JSON payload into a v4.public token.
func (p *PublicV4Encoder) Encode(payload string) (string, error) {
	if p.privateKey == nil {
		return "", errPrivateKeyRequired()
	}
	token, err := newTokenFromPayload(payload)
	if err != nil {
		return "", err
	}
	return token.V4Sign(*p.privateKey, nil), nil
}

// Decode verifies a v4.public token and returns its claims as indented JSON.
//
// The token's signature is verified. Claims are validated only when the
// decoder was built WithValidation; by default an expired token decodes
// successfully.
func (p *PublicV4Encoder) Decode(tokenString string) (string, error) {
	parser := p.parser()
	token, err := parser.ParseV4Public(p.publicKey, tokenString, nil)
	if err != nil {
		return "", wrapDecodeError(err)
	}
	return claimsJSON(token)
}

// PublicV3Encoder encodes and decodes PASETO V3 public (NIST P-384) tokens.
//
// A value built from a public key can only decode; Encode reports
// ErrInvalidKey in that case.
type PublicV3Encoder struct {
	validator

	privateKey *paseto.V3AsymmetricSecretKey
	publicKey  paseto.V3AsymmetricPublicKey
}

// NewPublicV3EncoderFromPrivateKey creates a PASETO V3 public encoder/decoder
// from a NIST P-384 private key file.
//
// The file may be a SEC 1 "EC PRIVATE KEY" PEM block (as produced by
// "openssl ecparam -genkey"), a PKCS#8 "PRIVATE KEY" PEM block (as produced by
// "openssl genpkey"), or 48 raw key bytes.
func NewPublicV3EncoderFromPrivateKey(privateKeyFile string, opts ...Option) (*PublicV3Encoder, error) {
	ecKey, rawBytes, err := loadECDSAP384PrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}

	// Note: go-paseto returns a usable *random* key alongside a non-nil error,
	// so this error must never be ignored or the token would be signed with a
	// key the caller never chose.
	var privateKey paseto.V3AsymmetricSecretKey
	if ecKey != nil {
		privateKey, err = paseto.NewV3AsymmetricSecretKeyFromEcdsa(*ecKey)
	} else {
		privateKey, err = paseto.NewV3AsymmetricSecretKeyFromBytes(rawBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &PublicV3Encoder{
		privateKey: &privateKey,
		publicKey:  privateKey.Public(),
		validator:  newValidator(opts),
	}, nil
}

// NewPublicV3DecoderFromPublicKey creates a PASETO V3 public decoder from a
// NIST P-384 public key file, in PKIX PEM form (as produced by
// "openssl ec -pubout") or as 49 raw compressed-point bytes.
func NewPublicV3DecoderFromPublicKey(publicKeyFile string, opts ...Option) (*PublicV3Encoder, error) {
	ecKey, rawBytes, err := loadECDSAP384PublicKey(publicKeyFile)
	if err != nil {
		return nil, err
	}

	// See the note in NewPublicV3EncoderFromPrivateKey: the error is load-bearing.
	var publicKey paseto.V3AsymmetricPublicKey
	if ecKey != nil {
		publicKey, err = paseto.NewV3AsymmetricPublicKeyFromEcdsa(*ecKey)
	} else {
		publicKey, err = paseto.NewV3AsymmetricPublicKeyFromBytes(rawBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &PublicV3Encoder{
		publicKey: publicKey,
		validator: newValidator(opts),
	}, nil
}

// Encode signs the JSON payload into a v3.public token.
func (p *PublicV3Encoder) Encode(payload string) (string, error) {
	if p.privateKey == nil {
		return "", errPrivateKeyRequired()
	}
	token, err := newTokenFromPayload(payload)
	if err != nil {
		return "", err
	}
	return token.V3Sign(*p.privateKey, nil), nil
}

// Decode verifies a v3.public token and returns its claims as indented JSON.
//
// The token's signature is verified. Claims are validated only when the
// decoder was built WithValidation; by default an expired token decodes
// successfully.
func (p *PublicV3Encoder) Decode(tokenString string) (string, error) {
	parser := p.parser()
	token, err := parser.ParseV3Public(p.publicKey, tokenString, nil)
	if err != nil {
		return "", wrapDecodeError(err)
	}
	return claimsJSON(token)
}

// PublicV2Encoder encodes and decodes PASETO V2 public (Ed25519) tokens.
//
// A value built from a public key can only decode; Encode reports
// ErrInvalidKey in that case.
type PublicV2Encoder struct {
	validator

	privateKey *paseto.V2AsymmetricSecretKey
	publicKey  paseto.V2AsymmetricPublicKey
}

// NewPublicV2EncoderFromPrivateKey creates a PASETO V2 public encoder/decoder
// from an Ed25519 private key file, in PKCS#8 PEM or raw form.
func NewPublicV2EncoderFromPrivateKey(privateKeyFile string, opts ...Option) (*PublicV2Encoder, error) {
	keyBytes, err := loadEd25519PrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}

	privateKey, err := paseto.NewV2AsymmetricSecretKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &PublicV2Encoder{
		privateKey: &privateKey,
		publicKey:  privateKey.Public(),
		validator:  newValidator(opts),
	}, nil
}

// NewPublicV2DecoderFromPublicKey creates a PASETO V2 public decoder from an
// Ed25519 public key file, in PKIX PEM or raw form.
func NewPublicV2DecoderFromPublicKey(publicKeyFile string, opts ...Option) (*PublicV2Encoder, error) {
	keyBytes, err := loadEd25519PublicKey(publicKeyFile)
	if err != nil {
		return nil, err
	}

	publicKey, err := paseto.NewV2AsymmetricPublicKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}

	return &PublicV2Encoder{
		publicKey: publicKey,
		validator: newValidator(opts),
	}, nil
}

// Encode signs the JSON payload into a v2.public token.
func (p *PublicV2Encoder) Encode(payload string) (string, error) {
	if p.privateKey == nil {
		return "", errPrivateKeyRequired()
	}
	token, err := newTokenFromPayload(payload)
	if err != nil {
		return "", err
	}
	// PASETO V2 has no implicit assertion parameter.
	return token.V2Sign(*p.privateKey), nil
}

// Decode verifies a v2.public token and returns its claims as indented JSON.
//
// The token's signature is verified. Claims are validated only when the
// decoder was built WithValidation; by default an expired token decodes
// successfully.
func (p *PublicV2Encoder) Decode(tokenString string) (string, error) {
	parser := p.parser()
	token, err := parser.ParseV2Public(p.publicKey, tokenString)
	if err != nil {
		return "", wrapDecodeError(err)
	}
	return claimsJSON(token)
}
