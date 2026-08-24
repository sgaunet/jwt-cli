// Package keyfile reads key material from disk under a size bound.
//
// os.ReadFile sizes its buffer to the whole file before returning, so an
// operator who points a key flag at a huge file — or at an endless device like
// /dev/zero — grows the process until it is OOM-killed, before any PEM parsing
// runs. Read bounds that allocation.
package keyfile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxSize is the largest key file Read accepts. A PEM-encoded key is a few KB
// at most, so 1 MiB leaves generous headroom for anything legitimate.
const MaxSize = 1 << 20 // 1 MiB

// ErrTooLarge indicates the file exceeded MaxSize. Callers wrap it in their own
// package's sentinel, so it stays matchable from outside internal/.
var ErrTooLarge = errors.New("key file too large")

// Read returns the contents of path, refusing anything larger than MaxSize
// rather than truncating it silently.
//
// Only the size is bounded. Non-regular files are deliberately still accepted:
// process substitution (--private-key <(cat key.pem)) and /dev/stdin are FIFOs,
// and rejecting them would break a legitimate way to pass a key.
//
// Open and read failures are returned bare: the caller adds the key-role
// context, and *os.PathError already names the path, so wrapping here would
// only duplicate it.
//
//nolint:wrapcheck // see the note above
func Read(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied file path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Read one byte past the limit, so an oversized file is detectable instead
	// of arriving silently truncated at exactly MaxSize.
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, path, MaxSize)
	}
	return data, nil
}
