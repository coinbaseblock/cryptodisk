package mount

import "errors"

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
