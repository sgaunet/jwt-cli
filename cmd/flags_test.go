package cmd

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

// everyFlagName lists every flag any leaf command declares. Each test case names
// the flags its command should have, and this list turns the remainder into
// must-be-absent assertions - so the table pins an exact set, not a subset.
//
// That exactness is the point: these flags used to be persistent on the encode
// and decode groups, so all nine algorithm leaves inherited all of them and
// "encode rs256 --secret x" parsed happily and ignored the secret.
var everyFlagName = []string{
	flagPayload, aliasPayload,
	flagSecret, aliasSecret,
	flagToken, aliasToken,
	flagPrivateKey, aliasPrivateKey,
	flagPublicKey, aliasPublicKey,
	flagKey,
	flagVersion,
	flagAllowWeakSecret,
	flagAllowWeakKey,
	flagValidateClaims,
	flagClockSkew,
}

// leafFlagCase is one command and the exact set of flags it declares itself.
type leafFlagCase struct {
	name string
	cmd  *cobra.Command
	want []string
}

// hsEncodeFlags and friends spell out one expected set per command family, so a
// family's nine-or-fewer members cannot drift apart from each other.
var (
	hsEncodeFlags = []string{flagPayload, aliasPayload, flagSecret, aliasSecret, flagAllowWeakSecret}
	hsDecodeFlags = []string{
		flagToken, aliasToken, flagSecret, aliasSecret, flagAllowWeakSecret,
		flagValidateClaims, flagClockSkew,
	}
	rsEncodeFlags = []string{flagPayload, aliasPayload, flagPrivateKey, aliasPrivateKey, flagAllowWeakKey}
	rsDecodeFlags = []string{
		flagToken, aliasToken, flagPrivateKey, aliasPrivateKey, flagPublicKey, aliasPublicKey,
		flagAllowWeakKey, flagValidateClaims, flagClockSkew,
	}
	// The ES sets are the RS sets without --allow-weak-key: an ECDSA key size is
	// fixed by the curve the algorithm names, so there is nothing to override.
	esEncodeFlags = []string{flagPayload, aliasPayload, flagPrivateKey, aliasPrivateKey}
	esDecodeFlags = []string{
		flagToken, aliasToken, flagPrivateKey, aliasPrivateKey, flagPublicKey, aliasPublicKey,
		flagValidateClaims, flagClockSkew,
	}
)

// leafFlagCases enumerates all 22 leaf commands.
func leafFlagCases() []leafFlagCase {
	return []leafFlagCase{
		{"encode hs256", encodeHS256Cmd, hsEncodeFlags},
		{"encode hs384", encodeHS384Cmd, hsEncodeFlags},
		{"encode hs512", encodeHS512Cmd, hsEncodeFlags},
		{"decode hs256", decodeHS256Cmd, hsDecodeFlags},
		{"decode hs384", decodeHS384Cmd, hsDecodeFlags},
		{"decode hs512", decodeHS512Cmd, hsDecodeFlags},
		{"encode rs256", encodeRS256Cmd, rsEncodeFlags},
		{"encode rs384", encodeRS384Cmd, rsEncodeFlags},
		{"encode rs512", encodeRS512Cmd, rsEncodeFlags},
		{"decode rs256", decodeRS256Cmd, rsDecodeFlags},
		{"decode rs384", decodeRS384Cmd, rsDecodeFlags},
		{"decode rs512", decodeRS512Cmd, rsDecodeFlags},
		{"encode es256", encodeES256Cmd, esEncodeFlags},
		{"encode es384", encodeES384Cmd, esEncodeFlags},
		{"encode es512", encodeES512Cmd, esEncodeFlags},
		{"decode es256", decodeES256Cmd, esDecodeFlags},
		{"decode es384", decodeES384Cmd, esDecodeFlags},
		{"decode es512", decodeES512Cmd, esDecodeFlags},
		{
			"paseto encode local", pasetoEncodeLocalCmd,
			[]string{flagPayload, aliasPayload, flagKey, flagVersion},
		},
		{
			"paseto encode public", pasetoEncodePublicCmd,
			[]string{flagPayload, aliasPayload, flagPrivateKey, aliasPrivateKey, flagVersion},
		},
		{
			"paseto decode local", pasetoDecodeLocalCmd,
			[]string{flagToken, aliasToken, flagKey, flagVersion, flagValidateClaims, flagClockSkew},
		},
		{
			"paseto decode public", pasetoDecodePublicCmd,
			[]string{
				flagToken, aliasToken, flagPrivateKey, aliasPrivateKey, flagPublicKey, aliasPublicKey,
				flagVersion, flagValidateClaims, flagClockSkew,
			},
		},
	}
}

// TestLeafCommandsDeclareExactlyTheirOwnFlags pins the flag set of every leaf.
//
// LocalFlags, not Flags, is deliberate: it excludes flags inherited from a
// parent, so --json does not show up here and the assertion is about what the
// leaf itself declares.
func TestLeafCommandsDeclareExactlyTheirOwnFlags(t *testing.T) {
	for _, tt := range leafFlagCases() {
		t.Run(tt.name, func(t *testing.T) {
			local := tt.cmd.LocalFlags()

			for _, name := range tt.want {
				if local.Lookup(name) == nil {
					t.Errorf("%q should declare --%s, but does not", tt.name, name)
				}
			}
			for _, name := range everyFlagName {
				if slices.Contains(tt.want, name) {
					continue
				}
				if local.Lookup(name) != nil {
					t.Errorf("%q declares --%s, which it never reads", tt.name, name)
				}
			}
		})
	}
}

// TestDecodeCommandsDeclareClaimsValidationFlags is the regression test for the
// drift that hid a real bug: the deleted registerDecodeFlags test helper omitted
// --validate-claims and --clock-skew even though the decode commands read them,
// so every cmd-level claims test silently ran with validation switched off. The
// factories now register what they read, and this pins it.
func TestDecodeCommandsDeclareClaimsValidationFlags(t *testing.T) {
	decoders := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"decode hs256", decodeHS256Cmd},
		{"decode hs384", decodeHS384Cmd},
		{"decode hs512", decodeHS512Cmd},
		{"decode rs256", decodeRS256Cmd},
		{"decode rs384", decodeRS384Cmd},
		{"decode rs512", decodeRS512Cmd},
		{"decode es256", decodeES256Cmd},
		{"decode es384", decodeES384Cmd},
		{"decode es512", decodeES512Cmd},
		{"paseto decode local", pasetoDecodeLocalCmd},
		{"paseto decode public", pasetoDecodePublicCmd},
	}

	for _, tt := range decoders {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{flagValidateClaims, flagClockSkew} {
				if tt.cmd.LocalFlags().Lookup(name) == nil {
					t.Errorf("%q reads --%s but does not declare it", tt.name, name)
				}
			}
		})
	}
}

// TestEncodeCommandsRejectDecodeOnlyFlags pins that --validate-claims and
// --clock-skew stay off the encode commands, where they would be meaningless.
func TestEncodeCommandsRejectDecodeOnlyFlags(t *testing.T) {
	encoders := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"encode hs256", encodeHS256Cmd},
		{"encode rs256", encodeRS256Cmd},
		{"encode es256", encodeES256Cmd},
		{"paseto encode local", pasetoEncodeLocalCmd},
		{"paseto encode public", pasetoEncodePublicCmd},
	}

	for _, tt := range encoders {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{flagValidateClaims, flagClockSkew} {
				if tt.cmd.LocalFlags().Lookup(name) != nil {
					t.Errorf("%q declares --%s, which only decoding uses", tt.name, name)
				}
			}
		})
	}
}
