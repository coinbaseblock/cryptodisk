package mount

import (
	"fmt"
	"sync"
)

const sectorSize = 512

// BlockDev translates sector-level (LBA) reads and writes into extent-level
// operations on an ExtentStore. It handles partial-extent reads/writes and
// multi-extent spanning operations.
type BlockDev struct {
	mu            sync.Mutex
	store         ExtentStore
	diskSize      uint64 // logical disk size in bytes
	extentSize    uint32 // plaintext extent size in bytes
	sectorsPerExt uint64 // sectors per extent
}

// NewBlockDev creates a block device backed by the given extent store.
func NewBlockDev(store ExtentStore, diskSizeBytes uint64, extentSize uint32) *BlockDev {
	return &BlockDev{
		store:         store,
		diskSize:      diskSizeBytes,
		extentSize:    extentSize,
		sectorsPerExt: uint64(extentSize) / sectorSize,
	}
}

// DiskSizeBytes returns the logical disk size.
func (bd *BlockDev) DiskSizeBytes() uint64 { return bd.diskSize }

// SectorSize returns the sector size (always 512).
func (bd *BlockDev) SectorSize() uint32 { return sectorSize }

// ReadAt reads len(buf) bytes starting at byte offset off.
// It translates the byte range into extent reads.
func (bd *BlockDev) ReadAt(buf []byte, off int64) (int, error) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	if off < 0 || uint64(off) >= bd.diskSize {
		return 0, fmt.Errorf("read offset %d out of range [0, %d)", off, bd.diskSize)
	}

	total := 0
	remain := len(buf)
	pos := uint64(off)

	for remain > 0 && pos < bd.diskSize {
		extIdx := pos / uint64(bd.extentSize)
		extOff := pos % uint64(bd.extentSize)
		chunk := int(uint64(bd.extentSize) - extOff)
		if chunk > remain {
			chunk = remain
		}
		if pos+uint64(chunk) > bd.diskSize {
			chunk = int(bd.diskSize - pos)
		}

		plain, err := bd.store.ReadExtent(extIdx)
		if err != nil {
			return total, fmt.Errorf("read extent %d: %w", extIdx, err)
		}

		copy(buf[total:total+chunk], plain[extOff:extOff+uint64(chunk)])
		total += chunk
		pos += uint64(chunk)
		remain -= chunk
	}
	return total, nil
}

// WriteAt writes len(buf) bytes starting at byte offset off.
// It performs read-modify-write for partial extent updates.
func (bd *BlockDev) WriteAt(buf []byte, off int64) (int, error) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	if off < 0 || uint64(off) >= bd.diskSize {
		return 0, fmt.Errorf("write offset %d out of range [0, %d)", off, bd.diskSize)
	}

	total := 0
	remain := len(buf)
	pos := uint64(off)

	for remain > 0 && pos < bd.diskSize {
		extIdx := pos / uint64(bd.extentSize)
		extOff := pos % uint64(bd.extentSize)
		chunk := int(uint64(bd.extentSize) - extOff)
		if chunk > remain {
			chunk = remain
		}
		if pos+uint64(chunk) > bd.diskSize {
			chunk = int(bd.diskSize - pos)
		}

		var plain []byte
		if extOff != 0 || uint64(chunk) != uint64(bd.extentSize) {
			// Partial write: read-modify-write
			var err error
			plain, err = bd.store.ReadExtent(extIdx)
			if err != nil {
				return total, fmt.Errorf("read extent %d for RMW: %w", extIdx, err)
			}
		} else {
			plain = make([]byte, bd.extentSize)
		}

		copy(plain[extOff:extOff+uint64(chunk)], buf[total:total+chunk])

		if err := bd.store.WriteExtent(extIdx, plain); err != nil {
			return total, fmt.Errorf("write extent %d: %w", extIdx, err)
		}

		total += chunk
		pos += uint64(chunk)
		remain -= chunk
	}
	return total, nil
}

// Flush flushes dirty data if the underlying store supports it.
func (bd *BlockDev) Flush() error {
	if f, ok := bd.store.(Flusher); ok {
		return f.Flush()
	}
	return nil
}
