//go:build linux

package mount

// DefaultBackend returns the NBD-based mount backend on Linux.
func DefaultBackend() Backend { return newNBDBackend() }
