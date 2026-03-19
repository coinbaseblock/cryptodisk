package cache

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// memStore is an in-memory ExtentStore for testing.
type memStore struct {
	mu     sync.Mutex
	data   map[uint64][]byte
	reads  int
	writes int
	errOn  map[string]error // "read:N" or "write:N" -> error
}

func newMemStore() *memStore {
	return &memStore{
		data:  make(map[uint64][]byte),
		errOn: make(map[string]error),
	}
}

func (m *memStore) ReadExtent(extent uint64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if err, ok := m.errOn[errorKey("read", extent)]; ok {
		return nil, err
	}
	if d, ok := m.data[extent]; ok {
		return append([]byte(nil), d...), nil
	}
	return make([]byte, 4096), nil
}

func (m *memStore) WriteExtent(extent uint64, plain []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes++
	if err, ok := m.errOn[errorKey("write", extent)]; ok {
		return err
	}
	m.data[extent] = append([]byte(nil), plain...)
	return nil
}

func errorKey(op string, extent uint64) string {
	return op + ":" + string(rune('0'+extent))
}

func TestNew_MinCapacity(t *testing.T) {
	s := newMemStore()
	wb := New(s, 1)
	// Should clamp to minimum of 8
	if wb.capEntries < 8 {
		t.Errorf("cap = %d, want >= 8", wb.capEntries)
	}
}

func TestRead_CacheMiss(t *testing.T) {
	s := newMemStore()
	s.data[5] = []byte("hello")
	wb := New(s, 16)

	got, err := wb.Read(5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("got %q, want %q", got, "hello")
	}
	if s.reads != 1 {
		t.Errorf("reads = %d, want 1", s.reads)
	}
}

func TestRead_CacheHit(t *testing.T) {
	s := newMemStore()
	s.data[5] = []byte("hello")
	wb := New(s, 16)

	// First read: cache miss
	wb.Read(5)
	// Second read: cache hit
	got, err := wb.Read(5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("got %q, want %q", got, "hello")
	}
	if s.reads != 1 {
		t.Errorf("reads = %d, want 1 (second read should be cached)", s.reads)
	}
}

func TestRead_ReturnsCopy(t *testing.T) {
	s := newMemStore()
	s.data[0] = []byte("original")
	wb := New(s, 16)

	got, _ := wb.Read(0)
	got[0] = 'X' // Mutate

	got2, _ := wb.Read(0)
	if got2[0] == 'X' {
		t.Error("cache returned a mutable reference instead of a copy")
	}
}

func TestWrite_Basic(t *testing.T) {
	s := newMemStore()
	wb := New(s, 16)

	err := wb.Write(0, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	// Should be readable from cache without hitting store
	got, _ := wb.Read(0)
	if !bytes.Equal(got, []byte("data")) {
		t.Errorf("got %q, want %q", got, "data")
	}
	if s.reads != 0 {
		t.Errorf("reads = %d, want 0 (should be cached)", s.reads)
	}
}

func TestWrite_DirtyCombine(t *testing.T) {
	s := newMemStore()
	wb := New(s, 16)

	wb.Write(0, []byte("first"))
	wb.Write(0, []byte("second"))

	// Flush should write once
	wb.Flush()
	if s.writes != 1 {
		t.Errorf("writes = %d, want 1", s.writes)
	}
	if !bytes.Equal(s.data[0], []byte("second")) {
		t.Error("store should have latest value")
	}
}

func TestFlush_WritesDirtyOnly(t *testing.T) {
	s := newMemStore()
	s.data[0] = []byte("clean")
	wb := New(s, 16)

	// Read extent (not dirty)
	wb.Read(0)
	// Write different extent (dirty)
	wb.Write(1, []byte("dirty"))

	wb.Flush()
	// Only extent 1 should be written
	if s.writes != 1 {
		t.Errorf("writes = %d, want 1", s.writes)
	}
}

func TestFlush_ClearsDirtyFlag(t *testing.T) {
	s := newMemStore()
	wb := New(s, 16)

	wb.Write(0, []byte("data"))
	wb.Flush()
	s.writes = 0

	// Second flush should not write again
	wb.Flush()
	if s.writes != 0 {
		t.Errorf("writes = %d, want 0 after second flush", s.writes)
	}
}

func TestFlushExtent(t *testing.T) {
	s := newMemStore()
	wb := New(s, 16)

	wb.Write(0, []byte("zero"))
	wb.Write(1, []byte("one"))

	// Flush only extent 0
	wb.FlushExtent(0)
	if s.writes != 1 {
		t.Errorf("writes = %d, want 1", s.writes)
	}
	if !bytes.Equal(s.data[0], []byte("zero")) {
		t.Error("extent 0 should be flushed")
	}
	if _, ok := s.data[1]; ok {
		t.Error("extent 1 should NOT be flushed yet")
	}
}

func TestFlushExtent_NotCached(t *testing.T) {
	s := newMemStore()
	wb := New(s, 16)

	// Flushing a non-existent extent should be a no-op
	if err := wb.FlushExtent(99); err != nil {
		t.Fatal(err)
	}
}

func TestFlushExtent_NotDirty(t *testing.T) {
	s := newMemStore()
	s.data[0] = []byte("clean")
	wb := New(s, 16)

	wb.Read(0) // Cache it as clean
	wb.FlushExtent(0)
	if s.writes != 0 {
		t.Errorf("writes = %d, want 0 for clean extent", s.writes)
	}
}

func TestEviction(t *testing.T) {
	s := newMemStore()
	wb := New(s, 8) // Minimum cap = 8

	// Fill cache beyond capacity
	for i := uint64(0); i < 12; i++ {
		data := make([]byte, 4)
		data[0] = byte(i)
		wb.Write(i, data)
	}

	// Evicted dirty extents should have been flushed to store
	if s.writes < 4 {
		t.Errorf("writes = %d, want >= 4 (evicted extents should be flushed)", s.writes)
	}

	// The most recently written should still be cached
	s.reads = 0
	wb.Read(11) // Should be a cache hit
	if s.reads != 0 {
		t.Error("most recent extent should still be in cache")
	}
}

func TestEviction_FlushesOnEvict(t *testing.T) {
	s := newMemStore()
	wb := New(s, 8)

	// Write 8 entries to fill cache
	for i := uint64(0); i < 8; i++ {
		wb.Write(i, []byte{byte(i)})
	}
	// No eviction yet
	if s.writes != 0 {
		t.Errorf("writes = %d, want 0 before eviction", s.writes)
	}

	// Write one more to trigger eviction
	wb.Write(8, []byte{8})
	if s.writes != 1 {
		t.Errorf("writes = %d, want 1 (one eviction)", s.writes)
	}
}

func TestRead_StoreError(t *testing.T) {
	s := newMemStore()
	s.errOn[errorKey("read", 0)] = errors.New("disk error")
	wb := New(s, 16)

	_, err := wb.Read(0)
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestFlush_StoreError(t *testing.T) {
	s := newMemStore()
	wb := New(s, 16)

	wb.Write(0, []byte("data"))
	s.errOn[errorKey("write", 0)] = errors.New("disk error")

	err := wb.Flush()
	if err == nil {
		t.Fatal("expected error from store during flush")
	}
}

func TestConcurrent_ReadWrite(t *testing.T) {
	s := newMemStore()
	wb := New(s, 64)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		ext := uint64(i % 10)
		go func() {
			defer wg.Done()
			wb.Write(ext, []byte("data"))
		}()
		go func() {
			defer wg.Done()
			wb.Read(ext)
		}()
	}
	wg.Wait()

	if err := wb.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestWrite_ReadDirtyPromoted(t *testing.T) {
	s := newMemStore()
	s.data[0] = []byte("from-store")
	wb := New(s, 16)

	// Read from store (clean)
	wb.Read(0)
	// Overwrite (dirty)
	wb.Write(0, []byte("modified"))

	// Read should return modified data
	got, _ := wb.Read(0)
	if !bytes.Equal(got, []byte("modified")) {
		t.Errorf("got %q, want %q", got, "modified")
	}
}
