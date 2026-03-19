//go:build windows

package mount

import (
	"fmt"
	"sync"
)

// WinSpdBridge implements the Backend interface for Windows using WinSpd.
// TODO: integrate with actual WinSpd API when available.
type WinSpdBridge struct {
	mu     sync.Mutex
	mounts map[string]*BlockDev
}

func (b *WinSpdBridge) Mount(opts Options) error {
	if opts.Store == nil {
		return fmt.Errorf("mount: extent store is required")
	}

	bd := NewBlockDev(opts.Store, opts.DiskSizeBytes, opts.ExtentSize)

	b.mu.Lock()
	if b.mounts == nil {
		b.mounts = make(map[string]*BlockDev)
	}
	b.mounts[opts.MountPoint] = bd
	b.mu.Unlock()

	// TODO: Register bd with WinSpd as a virtual SCSI disk at opts.MountPoint.
	// The WinSpd StorageUnitCreate API should be called here to expose bd
	// as a block device, with Read/Write/Flush callbacks delegating to
	// bd.ReadAt, bd.WriteAt, and bd.Flush respectively.
	return ErrBackendMissing
}

func (b *WinSpdBridge) Unmount(mountPoint string) error {
	b.mu.Lock()
	bd, ok := b.mounts[mountPoint]
	if !ok {
		b.mu.Unlock()
		return fmt.Errorf("no active mount at %s", mountPoint)
	}
	delete(b.mounts, mountPoint)
	b.mu.Unlock()

	bd.Flush()
	// TODO: Call WinSpd StorageUnitDelete to detach the block device.
	return nil
}
