package cmd

import (
	"testing"
)

// TestRootCommand_HasSubcommands tests that all expected subcommands are registered
func TestRootCommand_HasSubcommands(t *testing.T) {
	expectedCommands := []string{"encode", "decode", "genkeys", "version"}

	for _, cmdName := range expectedCommands {
		cmd, _, err := rootCmd.Find([]string{cmdName})
		if err != nil {
			t.Errorf("Expected to find command '%s', got error: %v", cmdName, err)
			continue
		}
		if cmd == nil {
			t.Errorf("Expected to find command '%s', got nil", cmdName)
		}
	}
}

// TestRootCommand_EncodeHasAllAlgorithms tests that encode has all 9 algorithm subcommands
func TestRootCommand_EncodeHasAllAlgorithms(t *testing.T) {
	expectedAlgos := []string{"hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256", "es384", "es512"}

	for _, algo := range expectedAlgos {
		cmd, _, err := rootCmd.Find([]string{"encode", algo})
		if err != nil {
			t.Errorf("Expected to find 'encode %s' command, got error: %v", algo, err)
			continue
		}
		if cmd == nil {
			t.Errorf("Expected to find 'encode %s' command, got nil", algo)
		}
	}
}

// TestRootCommand_DecodeHasAllAlgorithms tests that decode has all 9 algorithm subcommands
func TestRootCommand_DecodeHasAllAlgorithms(t *testing.T) {
	expectedAlgos := []string{"hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256", "es384", "es512"}

	for _, algo := range expectedAlgos {
		cmd, _, err := rootCmd.Find([]string{"decode", algo})
		if err != nil {
			t.Errorf("Expected to find 'decode %s' command, got error: %v", algo, err)
			continue
		}
		if cmd == nil {
			t.Errorf("Expected to find 'decode %s' command, got nil", algo)
		}
	}
}

// TestRootCommand_GenkeysHasAllAlgorithms tests that genkeys has all 6 algorithm subcommands
func TestRootCommand_GenkeysHasAllAlgorithms(t *testing.T) {
	expectedAlgos := []string{"rs256", "rs384", "rs512", "es256", "es384", "es512"}

	for _, algo := range expectedAlgos {
		cmd, _, err := rootCmd.Find([]string{"genkeys", algo})
		if err != nil {
			t.Errorf("Expected to find 'genkeys %s' command, got error: %v", algo, err)
			continue
		}
		if cmd == nil {
			t.Errorf("Expected to find 'genkeys %s' command, got nil", algo)
		}
	}
}
