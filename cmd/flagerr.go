package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// misplacedFlagError rewrites "unknown flag: --x" when a subcommand of cmd does
// declare --x, so the report names where the flag belongs instead of denying it
// exists.
//
// Every flag except --json is declared by the leaf command that reads it, which
// is what makes a wrong-family flag an error rather than a silent no-op. The
// cost is that a flag written before the subcommand reaches the group, which has
// never heard of it. Cobra cannot route around that: its stripFlags only knows a
// flag is boolean at the level where the flag is declared, so in
// "encode --allow-weak-secret hs256" it reads hs256 as the flag's value, finds
// no subcommand left, and parses the flag against encode itself. Value-taking
// flags survive because their real value is consumed the same way, leaving the
// algorithm behind as the subcommand.
//
// The position requirement stays - Cobra offers no hook early enough to change
// it - but a bare "unknown flag" for a flag one word further right is a
// misleading way to state it.
//
// It is registered on rootCmd only: Cobra's FlagErrorFunc walks up to the
// nearest parent that has one, so the root registration covers every command.
func misplacedFlagError(cmd *cobra.Command, err error) error {
	var notExist *pflag.NotExistError
	if !errors.As(err, &notExist) {
		return err
	}

	owners, flag := subcommandsDeclaring(cmd, notExist.GetSpecifiedName())
	if len(owners) == 0 {
		return err
	}

	// The flag name and the list of subcommands are both unbounded, so they get
	// lines of their own instead of being spliced into a sentence that would
	// wrap unpredictably - nine algorithms accept --validate-claims.
	//
	//nolint:revive,staticcheck // User-facing error message with proper formatting
	return fmt.Errorf(`%w

Every flag except --json belongs to the subcommand that reads it, so
--%s has to come after the subcommand name, not before it.

  accepted by:  %s
  for example:  %s %s --%s ...`,
		err, flag, strings.Join(owners, ", "),
		cmd.CommandPath(), owners[0], flag)
}

// subcommandsDeclaring returns the names, relative to cmd, of the nearest
// descendants that declare the flag pflag rejected, together with the long name
// to call it by. The names are relative so the caller can splice them into a
// corrected command line.
//
// The search stops at the first depth that yields a match, since a flag declared
// by a group's grandchildren is not also declared by its children: the point is
// to name the level the flag has to follow, not every command that has it.
//
// A descendant's Flags() has not been merged with its parents' persistent flags
// yet - only the command Cobra is executing gets that - so a match here means
// the descendant declares the flag itself, and --json or --help cannot match.
func subcommandsDeclaring(cmd *cobra.Command, name string) ([]string, string) {
	prefix := cmd.CommandPath() + " "
	level := cmd.Commands()

	for len(level) > 0 {
		var owners []string
		var flag string
		var next []*cobra.Command

		for _, sub := range level {
			long, ok := canonicalFlagName(sub, name)
			if !ok {
				next = append(next, sub.Commands()...)
				continue
			}
			owners = append(owners, strings.TrimPrefix(sub.CommandPath(), prefix))
			// Every command in a family declares the flag from the same
			// registration function, so the long name is the same for all of
			// them and the last one wins harmlessly.
			flag = long
		}
		if len(owners) > 0 {
			return owners, flag
		}
		level = next
	}
	return nil, ""
}

// canonicalFlagName resolves the name pflag rejected to the long name of the
// live flag cmd declares for it, reporting whether cmd declares one at all.
//
// Two things make a plain Lookup wrong here. A shorthand arrives as its bare
// letter, and the deprecated aliases are themselves single letters - "--p" for
// what is now "-p" - so Lookup("p") finds the alias rather than the flag that
// replaced it. Pointing a user at a deprecated flag, or printing "--p" for a
// "-p" they typed, would be worse advice than the bare pflag report. Resolving
// to the long name of a live flag avoids both.
func canonicalFlagName(cmd *cobra.Command, name string) (string, bool) {
	if f := cmd.Flags().Lookup(name); f != nil && offerable(f) {
		return f.Name, true
	}
	// ShorthandLookup panics on a longer name, so the length is checked first.
	if len(name) == 1 {
		if f := cmd.Flags().ShorthandLookup(name); f != nil && offerable(f) {
			return f.Name, true
		}
	}
	return "", false
}

// offerable reports whether a flag is one to point a user at. MarkDeprecated
// hides a flag as well as marking it, so either field disqualifies it.
func offerable(f *pflag.Flag) bool {
	return f.Deprecated == "" && !f.Hidden
}
