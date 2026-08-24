package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// runVersionCmd invokes versionCmd.Run directly and returns what it printed to stdout.
// Note: executeCommand must not be used here. It calls Execute() on a subcommand, which
// cobra redirects to the root, and the root then parses os.Args (the -test.* flags)
// instead of the args set on the child, so versionCmd.Run never runs.
func runVersionCmd(t *testing.T, flags map[string]string) string {
	t.Helper()

	for name, value := range flags {
		if err := versionCmd.Flags().Set(name, value); err != nil {
			t.Fatalf("Failed to set flag %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		for name := range flags {
			if err := versionCmd.Flags().Set(name, "false"); err != nil {
				t.Errorf("Failed to reset flag %s: %v", name, err)
			}
		}
	})

	// Capture stdout by redirecting it temporarily
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	versionCmd.Run(versionCmd, []string{})

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	return strings.TrimSpace(buf.String())
}

// TestVersionCommand_Output tests that the default version output lists every build field
func TestVersionCommand_Output(t *testing.T) {
	output := runVersionCmd(t, nil)

	if output == "" {
		t.Fatal("Expected version output, got empty string")
	}

	for _, want := range []string{
		"jwt-cli version:", "Git commit:", "Build date:",
		"Go version:", "Platform:", "Compiler:",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("Expected output to contain %q, got: %s", want, output)
		}
	}
}

// TestVersionCommand_Short tests that --short prints only the version
func TestVersionCommand_Short(t *testing.T) {
	output := runVersionCmd(t, map[string]string{"short": "true"})

	if output != getVersionInfo().Version {
		t.Errorf("Expected only the version %q, got: %q", getVersionInfo().Version, output)
	}
	if strings.Contains(output, "Go version:") {
		t.Errorf("Expected no detailed fields with --short, got: %s", output)
	}
}

// TestVersionCommand_JSON tests that --json emits a decodable VersionInfo
func TestVersionCommand_JSON(t *testing.T) {
	output := runVersionCmd(t, map[string]string{"json": "true"})

	var got VersionInfo
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Expected valid JSON, got error %v for output: %s", err, output)
	}

	want := getVersionInfo()
	if got.Version != want.Version {
		t.Errorf("version = %q, want %q", got.Version, want.Version)
	}
	if got.GoVersion != want.GoVersion {
		t.Errorf("go_version = %q, want %q", got.GoVersion, want.GoVersion)
	}
	if got.Platform != want.Platform {
		t.Errorf("platform = %q, want %q", got.Platform, want.Platform)
	}
}

// TestApplyBuildSettings tests how embedded VCS build settings are merged into VersionInfo
func TestApplyBuildSettings(t *testing.T) {
	tests := []struct {
		name          string
		info          VersionInfo
		settings      []debug.BuildSetting
		wantCommit    string
		wantBuildDate string
	}{
		{
			name:          "nil settings keeps the defaults",
			info:          VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings:      nil,
			wantCommit:    "none",
			wantBuildDate: "unknown",
		},
		{
			name: "no vcs settings keeps the defaults",
			info: VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "GOOS", Value: "linux"},
				{Key: "-compiler", Value: "gc"},
			},
			wantCommit:    "none",
			wantBuildDate: "unknown",
		},
		{
			name: "revision longer than the short hash is truncated",
			info: VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			},
			wantCommit:    "01234567",
			wantBuildDate: "unknown",
		},
		{
			name: "revision exactly the short hash length is kept whole",
			info: VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "12345678"},
			},
			wantCommit:    "12345678",
			wantBuildDate: "unknown",
		},
		{
			name: "revision shorter than the short hash is kept as is",
			info: VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abc123"},
			},
			wantCommit:    "abc123",
			wantBuildDate: "unknown",
		},
		{
			name: "empty revision is kept as is",
			info: VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: ""},
			},
			wantCommit:    "",
			wantBuildDate: "unknown",
		},
		{
			name: "link-time commit is not overridden by vcs.revision",
			info: VersionInfo{Commit: "deadbeefcafebabe", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "0123456789abcdef"},
			},
			wantCommit:    "deadbeefcafebabe",
			wantBuildDate: "unknown",
		},
		{
			name: "vcs.time fills an unknown build date",
			info: VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "vcs.time", Value: "2024-01-02T03:04:05Z"},
			},
			wantCommit:    "none",
			wantBuildDate: "2024-01-02T03:04:05Z",
		},
		{
			name: "link-time build date is not overridden by vcs.time",
			info: VersionInfo{Commit: "none", BuildDate: "2020-05-05T00:00:00Z"},
			settings: []debug.BuildSetting{
				{Key: "vcs.time", Value: "2024-01-02T03:04:05Z"},
			},
			wantCommit:    "none",
			wantBuildDate: "2020-05-05T00:00:00Z",
		},
		{
			name: "revision and time are both applied",
			info: VersionInfo{Commit: "none", BuildDate: "unknown"},
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "fedcba9876543210"},
				{Key: "vcs.time", Value: "2024-01-02T03:04:05Z"},
				{Key: "vcs.modified", Value: "true"},
			},
			wantCommit:    "fedcba98",
			wantBuildDate: "2024-01-02T03:04:05Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyBuildSettings(tt.info, tt.settings)

			if got.Commit != tt.wantCommit {
				t.Errorf("Commit = %q, want %q", got.Commit, tt.wantCommit)
			}
			if got.BuildDate != tt.wantBuildDate {
				t.Errorf("BuildDate = %q, want %q", got.BuildDate, tt.wantBuildDate)
			}
		})
	}
}

// TestApplyBuildSettings_PreservesUnrelatedFields tests that only commit and build date can change
func TestApplyBuildSettings_PreservesUnrelatedFields(t *testing.T) {
	in := VersionInfo{
		Version:   "1.2.3",
		Commit:    "none",
		BuildDate: "unknown",
		GoVersion: "go1.26.0",
		Platform:  "linux/amd64",
		Compiler:  "gc",
	}

	got := applyBuildSettings(in, []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef"},
		{Key: "vcs.time", Value: "2024-01-02T03:04:05Z"},
	})

	if got.Version != in.Version {
		t.Errorf("Version = %q, want %q", got.Version, in.Version)
	}
	if got.GoVersion != in.GoVersion {
		t.Errorf("GoVersion = %q, want %q", got.GoVersion, in.GoVersion)
	}
	if got.Platform != in.Platform {
		t.Errorf("Platform = %q, want %q", got.Platform, in.Platform)
	}
	if got.Compiler != in.Compiler {
		t.Errorf("Compiler = %q, want %q", got.Compiler, in.Compiler)
	}
}

// TestGetVersionInfo tests that getVersionInfo reports the runtime values and non-empty build data
func TestGetVersionInfo(t *testing.T) {
	info := getVersionInfo()

	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	wantPlatform := runtime.GOOS + "/" + runtime.GOARCH
	if info.Platform != wantPlatform {
		t.Errorf("Platform = %q, want %q", info.Platform, wantPlatform)
	}
	if info.Compiler != runtime.Compiler {
		t.Errorf("Compiler = %q, want %q", info.Compiler, runtime.Compiler)
	}
	if info.Version == "" {
		t.Error("Expected a non-empty Version")
	}
	if info.BuildDate == "" {
		t.Error("Expected a non-empty BuildDate")
	}
}

// TestGetVersionInfo_UsesLinkTimeValues tests that ldflags-injected values are reported unchanged
func TestGetVersionInfo_UsesLinkTimeValues(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = oldVersion, oldCommit, oldBuildDate
	})

	version, commit, buildDate = "1.2.3", "abcdef1234567890", "2024-01-02T03:04:05Z"

	info := getVersionInfo()

	if info.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", info.Version, "1.2.3")
	}
	// Commit is not "none", so an embedded vcs.revision must neither replace nor truncate it
	if info.Commit != "abcdef1234567890" {
		t.Errorf("Commit = %q, want %q", info.Commit, "abcdef1234567890")
	}
	if info.BuildDate != "2024-01-02T03:04:05Z" {
		t.Errorf("BuildDate = %q, want %q", info.BuildDate, "2024-01-02T03:04:05Z")
	}
}
