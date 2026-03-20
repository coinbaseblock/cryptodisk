package mount

import (
	"errors"
	"strings"
)

// ExtentStore abstracts encrypted extent I/O. The container.Handle and
// cache.WriteBack types both satisfy this interface.
type ExtentStore interface {
	ReadExtent(extent uint64) ([]byte, error)
	WriteExtent(extent uint64, plain []byte) error
}

// Flusher is optionally implemented by stores that buffer writes (e.g. cache).
type Flusher interface {
	Flush() error
}

// Options carries everything the mount backend needs to expose a block device.
type Options struct {
	ContainerPath string
	MountPoint    string
	IdleSeconds   int
	CacheExtents  int

	// Store is the (optionally cached) extent store for block I/O.
	// Set by the CLI after password validation.
	Store ExtentStore

	// DiskSizeBytes is the logical disk size from the container header.
	DiskSizeBytes uint64

	// ExtentSize is the plaintext extent size in bytes.
	ExtentSize uint32
}

var ErrBackendMissing = errors.New("no block-device backend installed")

type Backend interface {
	Mount(opts Options) error
	Unmount(mountPoint string) error
}

// AvailabilityChecker is optionally implemented by backends that can
// preflight whether mounting is usable before the CLI asks for secrets.
type AvailabilityChecker interface {
	CheckAvailable() error
}

// CheckAvailable asks the backend whether mount support is usable in the
// current environment. Backends that do not implement AvailabilityChecker are
// treated as available so existing backends remain compatible.
func CheckAvailable(backend Backend) error {
	checker, ok := backend.(AvailabilityChecker)
	if !ok {
		return nil
	}
	return checker.CheckAvailable()
}

// NormalizeMountPoint canonicalizes a user-supplied mount target.
// Drive-letter mount points such as "x", "x:", "x:\", and " x:/ "
// are normalized to "X:" so both CLI and backend logic treat them
// consistently.
func NormalizeMountPoint(mountPoint string) string {
	s := strings.TrimSpace(mountPoint)
	s = strings.TrimRight(s, `\/`)
	if len(s) == 1 && isDriveLetter(s[0]) {
		return strings.ToUpper(s) + ":"
	}
	if len(s) == 2 && s[1] == ':' && isDriveLetter(s[0]) {
		return strings.ToUpper(s)
	}
	return s
}

func isDriveLetter(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	default:
		return false
	}
}
