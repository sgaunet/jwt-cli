package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// Flag names. Every flag is declared by the leaf command that reads it, so the
// name is written in this file and read in another; naming them once keeps a
// typo from becoming a silently empty flag.
const (
	flagPayload    = "payload"
	flagSecret     = "secret"
	flagToken      = "token"
	flagPrivateKey = "private-key"
	flagPublicKey  = "public-key"
	flagKey        = "key"
	flagVersion    = "version"
	//nolint:gosec // G101: a flag name, not a credential
	flagAllowWeakSecret = "allow-weak-secret"
	flagAllowWeakKey    = "allow-weak-key"
	flagValidateClaims  = "validate-claims"
	flagClockSkew       = "clock-skew"
)

// Deprecated long-form aliases kept for backward compatibility. Each is also the
// shorthand letter of the flag that replaced it, which is why they read as a
// single character.
const (
	aliasPayload    = "p"
	aliasSecret     = "s"
	aliasToken      = "t"
	aliasPrivateKey = "pk"
	aliasPublicKey  = "pubk"
)

// Flag usage strings. The JWT and PASETO wordings differ, so each family passes
// the one that belongs to it.
const (
	usagePayloadJWT    = "JSON payload to encode into JWT (e.g., '{\"user\":\"alice\"}')"
	usagePrivateKeyJWT = "path to RSA/ECDSA private key file in PEM format"
	usagePublicKeyJWT  = "path to RSA/ECDSA public key file in PEM format"
	//nolint:gosec // G101: help text, not a credential
	usageTokenJWT     = "JWT token to decode and verify"
	usageSecretEncode = "HMAC secret for signing (minimum 32 bytes for HS256, 48 bytes for HS384, 64 bytes for HS512)"
	usageSecretDecode = "HMAC secret for verification (minimum 32 bytes for HS256, 48 bytes for HS384, 64 bytes for HS512)"
	//nolint:gosec // G101: help text, not a credential
	usageAllowWeakSecret = "allow weak secrets for HMAC algorithms (for testing purposes only)"
	usageAllowWeakKey    = "allow RSA keys below 2048 bits for RSA algorithms (for testing purposes only)"
	usageValidateJWT     = "validate JWT time-based claims (exp, nbf, iat) - reject expired or not-yet-valid tokens"
	usageValidatePaseto  = "validate PASETO time-based claims (exp, nbf) - reject expired or not-yet-valid tokens"
	usageClockSkew       = "clock skew tolerance for claims validation (e.g., 5m, 30s)"

	usagePayloadPaseto    = "JSON payload to encode into the PASETO token (e.g., '{\"user\":\"alice\"}')"
	usagePrivateKeyPaseto = "path to Ed25519 (v2/v4) or P-384 (v3) private key file, PEM or raw"
	usagePublicKeyPaseto  = "path to Ed25519 (v2/v4) or P-384 (v3) public key file, PEM or raw"
	usageKeyPaseto        = "hex-encoded 32-byte symmetric key for local tokens"
	usageVersionPaseto    = "PASETO version (v2, v3, v4)"
	//nolint:gosec // G101: help text, not a credential
	usageTokenPaseto = "PASETO token to decode and verify"
)

// errNegativeClockSkew is the sentinel behind every negative --clock-skew
// report. Use errors.Is to test for it.
//
//nolint:revive,staticcheck // User-facing error message with proper formatting
var errNegativeClockSkew = errors.New(`Error: --clock-skew must not be negative`)

// clockSkewFlag reads --clock-skew, rejecting a negative duration.
//
// A negative value does not widen the validity window, it narrows it: the token
// would have to remain valid that far into the future. Nothing an operator
// reaching for a skew tolerance means, and it produced the confusing result of
// "token is expired" for a token that had not expired, so it is refused rather
// than silently honoured.
func clockSkewFlag(cmd *cobra.Command) (time.Duration, error) {
	skew, _ := cmd.Flags().GetDuration(flagClockSkew)
	if skew < 0 {
		//nolint:revive,staticcheck // User-facing error message with proper formatting
		return 0, fmt.Errorf(`%w: got %s

A skew tolerance widens the window a token is accepted in, so it must be zero or
positive.

Example usage:
  jwt-cli decode hs256 --token "$TOKEN" --secret "$SECRET" --validate-claims --clock-skew 5m`,
			errNegativeClockSkew, skew)
	}
	return skew, nil
}

// flagWithFallback reads a flag, falling back to its deprecated short alias.
func flagWithFallback(cmd *cobra.Command, name, deprecated string) string {
	value, _ := cmd.Flags().GetString(name)
	if value == "" {
		value, _ = cmd.Flags().GetString(deprecated) // Check deprecated flag
	}
	return value
}

// weakKeyOptOut reports whether --allow-weak-key was given.
//
// The ES commands do not register the flag at all, since an ECDSA key size is
// fixed by the curve the algorithm names. An absent flag therefore reads as
// false rather than as an error.
func weakKeyOptOut(cmd *cobra.Command) bool {
	allow, err := cmd.Flags().GetBool(flagAllowWeakKey)
	return err == nil && allow
}

// addDeprecatedAlias registers a hidden long-form alias for a renamed flag.
func addDeprecatedAlias(cmd *cobra.Command, name, message string) {
	cmd.Flags().String(name, "", "")
	_ = cmd.Flags().MarkDeprecated(name, message)
}

// addPayloadFlag registers --payload and its deprecated --p alias.
func addPayloadFlag(cmd *cobra.Command, usage string) {
	cmd.Flags().StringP(flagPayload, aliasPayload, "", usage)
	_ = cmd.MarkFlagFilename(flagPayload, "json")
	addDeprecatedAlias(cmd, aliasPayload, "use --payload or -p instead")
}

// addTokenFlag registers --token and its deprecated --t alias. The extensions
// drive shell completion.
func addTokenFlag(cmd *cobra.Command, usage string, extensions ...string) {
	cmd.Flags().StringP(flagToken, aliasToken, "", usage)
	_ = cmd.MarkFlagFilename(flagToken, extensions...)
	addDeprecatedAlias(cmd, aliasToken, "use --token or -t instead")
}

// addSecretFlag registers --secret and its deprecated --s alias.
func addSecretFlag(cmd *cobra.Command, usage string) {
	cmd.Flags().StringP(flagSecret, aliasSecret, "", usage)
	addDeprecatedAlias(cmd, aliasSecret, "use --secret or -s instead")
}

// addPrivateKeyFlag registers --private-key and its deprecated --pk alias.
func addPrivateKeyFlag(cmd *cobra.Command, usage string) {
	cmd.Flags().String(flagPrivateKey, "", usage)
	_ = cmd.MarkFlagFilename(flagPrivateKey, "pem", "key")
	addDeprecatedAlias(cmd, aliasPrivateKey, "use --private-key instead")
}

// addPublicKeyFlag registers --public-key and its deprecated --pubk alias.
func addPublicKeyFlag(cmd *cobra.Command, usage string) {
	cmd.Flags().String(flagPublicKey, "", usage)
	_ = cmd.MarkFlagFilename(flagPublicKey, "pem", "key")
	addDeprecatedAlias(cmd, aliasPublicKey, "use --public-key instead")
}

// addClaimsValidationFlags registers the pair of flags that govern time-based
// claims validation on a decode command.
func addClaimsValidationFlags(cmd *cobra.Command, validateUsage string) {
	cmd.Flags().Bool(flagValidateClaims, false, validateUsage)
	cmd.Flags().Duration(flagClockSkew, 0, usageClockSkew)
}

// addPasetoVersionFlag registers the --version flag shared by every paseto
// encode and decode command.
func addPasetoVersionFlag(cmd *cobra.Command) {
	cmd.Flags().String(flagVersion, pasetoV4, usageVersionPaseto)
}

// registerHSEncodeFlags declares the flags read by the HMAC encode commands.
func registerHSEncodeFlags(cmd *cobra.Command) {
	addPayloadFlag(cmd, usagePayloadJWT)
	addSecretFlag(cmd, usageSecretEncode)
	cmd.Flags().Bool(flagAllowWeakSecret, false, usageAllowWeakSecret)
}

// registerHSDecodeFlags declares the flags read by the HMAC decode commands.
func registerHSDecodeFlags(cmd *cobra.Command) {
	addTokenFlag(cmd, usageTokenJWT, "jwt", "txt")
	addSecretFlag(cmd, usageSecretDecode)
	cmd.Flags().Bool(flagAllowWeakSecret, false, usageAllowWeakSecret)
	addClaimsValidationFlags(cmd, usageValidateJWT)
}

// registerAsymmetricEncodeFlags declares the flags read by the RSA and ECDSA
// encode commands. allowWeakKey adds --allow-weak-key, which only RSA has a use
// for: an ECDSA key size is fixed by the curve, so the ES commands leave the
// flag unregistered and reject it as unknown.
func registerAsymmetricEncodeFlags(cmd *cobra.Command, allowWeakKey bool) {
	addPayloadFlag(cmd, usagePayloadJWT)
	addPrivateKeyFlag(cmd, usagePrivateKeyJWT)
	if allowWeakKey {
		cmd.Flags().Bool(flagAllowWeakKey, false, usageAllowWeakKey)
	}
}

// registerAsymmetricDecodeFlags declares the flags read by the RSA and ECDSA
// decode commands. See registerAsymmetricEncodeFlags for allowWeakKey.
func registerAsymmetricDecodeFlags(cmd *cobra.Command, allowWeakKey bool) {
	addTokenFlag(cmd, usageTokenJWT, "jwt", "txt")
	addPrivateKeyFlag(cmd, usagePrivateKeyJWT)
	addPublicKeyFlag(cmd, usagePublicKeyJWT)
	if allowWeakKey {
		cmd.Flags().Bool(flagAllowWeakKey, false, usageAllowWeakKey)
	}
	addClaimsValidationFlags(cmd, usageValidateJWT)
}

// registerPasetoEncodeLocalFlags declares the flags read by "paseto encode
// local". Local tokens are symmetric, so they take --key and no key pair.
func registerPasetoEncodeLocalFlags(cmd *cobra.Command) {
	addPayloadFlag(cmd, usagePayloadPaseto)
	cmd.Flags().String(flagKey, "", usageKeyPaseto)
	addPasetoVersionFlag(cmd)
}

// registerPasetoEncodePublicFlags declares the flags read by "paseto encode
// public". Signing needs the private key of a pair, never the symmetric --key.
func registerPasetoEncodePublicFlags(cmd *cobra.Command) {
	addPayloadFlag(cmd, usagePayloadPaseto)
	addPrivateKeyFlag(cmd, usagePrivateKeyPaseto)
	addPasetoVersionFlag(cmd)
}

// registerPasetoDecodeLocalFlags declares the flags read by "paseto decode
// local".
func registerPasetoDecodeLocalFlags(cmd *cobra.Command) {
	addTokenFlag(cmd, usageTokenPaseto, "paseto", "txt")
	cmd.Flags().String(flagKey, "", usageKeyPaseto)
	addPasetoVersionFlag(cmd)
	addClaimsValidationFlags(cmd, usageValidatePaseto)
}

// registerPasetoDecodePublicFlags declares the flags read by "paseto decode
// public". Either key of the pair verifies a signature, and the public key wins
// when both are supplied.
func registerPasetoDecodePublicFlags(cmd *cobra.Command) {
	addTokenFlag(cmd, usageTokenPaseto, "paseto", "txt")
	addPrivateKeyFlag(cmd, usagePrivateKeyPaseto)
	addPublicKeyFlag(cmd, usagePublicKeyPaseto)
	addPasetoVersionFlag(cmd)
	addClaimsValidationFlags(cmd, usageValidatePaseto)
}
