package keyfile_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/internal/keyfile"
)

// writeSizedFile creates a file of exactly size bytes. It truncates rather than
// writing the bytes out, so a multi-megabyte fixture costs nothing.
func writeSizedFile(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("Failed to create fixture: %v", err)
	}
	if err := os.Truncate(path, size); err != nil {
		t.Fatalf("Failed to size fixture to %d bytes: %v", size, err)
	}
	return path
}

func TestReadReturnsFileContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	want := []byte("-----BEGIN PUBLIC KEY-----\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("Failed to create fixture: %v", err)
	}

	got, err := keyfile.Read(path)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Expected %q, got %q", want, got)
	}
}

// TestReadAtMaxSize guards the boundary: a file of exactly MaxSize is still a
// valid read, and comes back whole rather than one byte short.
func TestReadAtMaxSize(t *testing.T) {
	got, err := keyfile.Read(writeSizedFile(t, keyfile.MaxSize))
	if err != nil {
		t.Fatalf("Expected a file of exactly MaxSize to be accepted, got: %v", err)
	}
	if len(got) != keyfile.MaxSize {
		t.Errorf("Expected %d bytes, got %d", keyfile.MaxSize, len(got))
	}
}

func TestReadAboveMaxSizeIsRejected(t *testing.T) {
	path := writeSizedFile(t, keyfile.MaxSize+1)

	got, err := keyfile.Read(path)
	if err == nil {
		t.Fatal("Expected an error for a file above MaxSize, got nil")
	}
	if !errors.Is(err, keyfile.ErrTooLarge) {
		t.Errorf("Expected errors.Is(err, ErrTooLarge), got: %v", err)
	}
	// The caller must not receive a truncated key: rejecting beats truncating.
	if got != nil {
		t.Errorf("Expected no data alongside the error, got %d bytes", len(got))
	}
	if !strings.Contains(err.Error(), "1048576 bytes") {
		t.Errorf("Expected the error to name the limit, got: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("Expected the error to name the file, got: %v", err)
	}
}

// TestReadMissingFile pins that the underlying cause stays reachable, which the
// cryptojwt package doc promises for os.ErrNotExist.
func TestReadMissingFile(t *testing.T) {
	_, err := keyfile.Read(filepath.Join(t.TempDir(), "does-not-exist.pem"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected errors.Is(err, os.ErrNotExist), got: %v", err)
	}
}
