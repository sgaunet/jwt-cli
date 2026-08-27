package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// jwtAlgorithms lists the JWT algorithms, for argument validation and shell
// completion. The encode, decode and genkeys groups all accept the same set.
var jwtAlgorithms = []string{
	"hs256", "hs384", "hs512",
	"rs256", "rs384", "rs512",
	"es256", "es384", "es512",
}

// oneValidSubcommand is the Args validator of every command group.
//
// Cobra dispatches a known subcommand before Args runs, so this only ever sees a
// word that matched no subcommand. OnlyValidArgs rejects it against the group's
// ValidArgs, adding a "Did you mean this?" hint. MaximumNArgs(1) is unreachable
// while every ValidArgs entry is a real subcommand, and is kept as a cheap
// invariant.
var oneValidSubcommand = cobra.MatchAll(cobra.OnlyValidArgs, cobra.MaximumNArgs(1))

// showGroupHelp is the RunE of every command group.
//
// The groups need a RunE at all for their Args validator to run: Cobra checks
// Runnable() before it validates positional arguments (cobra command.go, the
// !c.Runnable() short-circuit precedes ValidateArgs) and turns a non-runnable
// command into help text plus a nil error. That is why "jwt-cli encode hs257"
// used to print help and exit 0, which let a scripted "cmd || exit 1" pass while
// verifying nothing.
//
// Reaching this function means no subcommand was named at all, which stays a
// help-and-exit-0 case: a bare group is how the algorithms are discovered.
func showGroupHelp(cmd *cobra.Command, _ []string) error {
	if err := cmd.Help(); err != nil {
		return fmt.Errorf("failed to print help: %w", err)
	}
	return nil
}

// requireValidSubcommand applies the group behaviour to cmd: reject a word that
// is not one of its subcommands, and print help when none is given.
//
// Every group must also declare ValidArgs, since OnlyValidArgs accepts anything
// when that list is empty.
func requireValidSubcommand(cmd *cobra.Command) {
	cmd.Args = oneValidSubcommand
	cmd.RunE = showGroupHelp
	// A runnable command otherwise gets "[flags]" appended to its usage line,
	// which would advertise flags these groups no longer declare.
	cmd.DisableFlagsInUseLine = true
}
