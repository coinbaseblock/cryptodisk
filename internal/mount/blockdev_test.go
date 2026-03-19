package mount

import (
	"bytes"
	"testing"
)

// memExtentStore is a simple in-memory extent store for testing.
type memExtentStore struct {
	extentSize int
	extents    map[uint64][]byte
	flushCount int
}

func newMemExtentStore(extentSize int) *memExtentStore {
	return &memExtentStore{
		extentSize: extentSize,
		extents:    make(map[uint64][]byte),
	}
}

func (m *memExtentStore) ReadExtent(extent uint64) ([]byte, error) {
	if d, ok := m.extents[extent]; ok {
		return append([]byte(nil), d...), nil
	}
	return make([]byte, m.extentSize), nil
}

func (m *memExtentStore) WriteExtent(extent uint64, plain []byte) error {
	m.extents[extent] = append([]byte(nil), plain...)
	return nil
}

func (m *memExtentStore) Flush() error {
	m.flushCount++
	return nil
}

func TestBlockDev_ReadWriteAligned(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096) // 10 extents

	// Write exactly one extent worth of data
	data := make([]byte, 4096)
	for i := range data {
		data[i] = 0xAB
	}
	n, err := bd.WriteAt(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4096 {
		t.Errorf("wrote %d, want 4096", n)
	}

	// Read it back
	buf := make([]byte, 4096)
	n, err = bd.ReadAt(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4096 {
		t.Errorf("read %d, want 4096", n)
	}
	if !bytes.Equal(buf, data) {
		t.Error("data mismatch")
	}
}

func TestBlockDev_ReadWritePartialExtent(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	// Write 512 bytes at offset 100 (partial extent)
	data := make([]byte, 512)
	for i := range data {
		data[i] = 0xCD
	}
	n, err := bd.WriteAt(data, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 512 {
		t.Errorf("wrote %d, want 512", n)
	}

	// Read back
	buf := make([]byte, 512)
	n, err = bd.ReadAt(buf, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, data) {
		t.Error("partial data mismatch")
	}

	// Verify the surrounding bytes are zero
	full := make([]byte, 4096)
	bd.ReadAt(full, 0)
	for i := 0; i < 100; i++ {
		if full[i] != 0 {
			t.Errorf("byte %d should be 0, got %d", i, full[i])
			break
		}
	}
	for i := 612; i < 4096; i++ {
		if full[i] != 0 {
			t.Errorf("byte %d should be 0, got %d", i, full[i])
			break
		}
	}
}

func TestBlockDev_ReadWriteSpanExtents(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	// Write data that spans two extents
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte(i % 256)
	}
	// Write at offset 3072 (1024 bytes before extent boundary)
	n, err := bd.WriteAt(data, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2048 {
		t.Errorf("wrote %d, want 2048", n)
	}

	// Read it back
	buf := make([]byte, 2048)
	n, err = bd.ReadAt(buf, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2048 {
		t.Errorf("read %d, want 2048", n)
	}
	if !bytes.Equal(buf, data) {
		t.Error("spanning data mismatch")
	}
}

func TestBlockDev_ReadOutOfRange(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	buf := make([]byte, 512)
	_, err := bd.ReadAt(buf, int64(4096*10)) // At the end boundary
	if err == nil {
		t.Error("expected error for out-of-range read")
	}
}

func TestBlockDev_WriteOutOfRange(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	_, err := bd.WriteAt(make([]byte, 512), int64(4096*10))
	if err == nil {
		t.Error("expected error for out-of-range write")
	}
}

func TestBlockDev_NegativeOffset(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	_, err := bd.ReadAt(make([]byte, 512), -1)
	if err == nil {
		t.Error("expected error for negative offset")
	}
}

func TestBlockDev_DiskSizeAndSectorSize(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 1<<30, 4096)

	if bd.DiskSizeBytes() != 1<<30 {
		t.Errorf("disk size = %d, want %d", bd.DiskSizeBytes(), 1<<30)
	}
	if bd.SectorSize() != 512 {
		t.Errorf("sector size = %d, want 512", bd.SectorSize())
	}
}

func TestBlockDev_Flush(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	bd.WriteAt(make([]byte, 4096), 0)
	if err := bd.Flush(); err != nil {
		t.Fatal(err)
	}
	if store.flushCount != 1 {
		t.Errorf("flush count = %d, want 1", store.flushCount)
	}
}

func TestBlockDev_FlushNoFlusher(t *testing.T) {
	// Use a store that doesn't implement Flusher
	store := &noFlushStore{data: make(map[uint64][]byte), extentSize: 4096}
	bd := NewBlockDev(store, 4096*10, 4096)

	// Flush should be a no-op
	if err := bd.Flush(); err != nil {
		t.Fatal(err)
	}
}

type noFlushStore struct {
	data       map[uint64][]byte
	extentSize int
}

func (s *noFlushStore) ReadExtent(extent uint64) ([]byte, error) {
	if d, ok := s.data[extent]; ok {
		return append([]byte(nil), d...), nil
	}
	return make([]byte, s.extentSize), nil
}

func (s *noFlushStore) WriteExtent(extent uint64, plain []byte) error {
	s.data[extent] = append([]byte(nil), plain...)
	return nil
}

func TestBlockDev_MultipleExtentsSequential(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*100, 4096)

	// Write distinct data across multiple extents
	for i := 0; i < 5; i++ {
		data := make([]byte, 4096)
		for j := range data {
			data[j] = byte(i)
		}
		bd.WriteAt(data, int64(i*4096))
	}

	// Read back and verify
	for i := 0; i < 5; i++ {
		buf := make([]byte, 4096)
		bd.ReadAt(buf, int64(i*4096))
		for j, b := range buf {
			if b != byte(i) {
				t.Errorf("extent %d byte %d = %d, want %d", i, j, b, byte(i))
				break
			}
		}
	}
}

func TestBlockDev_LargeSpanningWrite(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*100, 4096)

	// Write 12288 bytes (3 extents) starting at offset 2048 (mid-extent)
	data := make([]byte, 12288)
	for i := range data {
		data[i] = byte(i % 256)
	}
	n, err := bd.WriteAt(data, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if n != 12288 {
		t.Errorf("wrote %d, want 12288", n)
	}

	buf := make([]byte, 12288)
	n, err = bd.ReadAt(buf, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if n != 12288 {
		t.Errorf("read %d, want 12288", n)
	}
	if !bytes.Equal(buf, data) {
		t.Error("large spanning data mismatch")
	}
}

func TestBlockDev_ReadUnwritten(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	buf := make([]byte, 4096)
	n, err := bd.ReadAt(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4096 {
		t.Errorf("read %d, want 4096", n)
	}
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte %d = %d, want 0", i, b)
			break
		}
	}
}
