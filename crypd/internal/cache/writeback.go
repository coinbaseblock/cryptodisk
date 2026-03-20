package cache

import (
	"container/list"
	"errors"
	"sync"
	"time"
)

type ExtentStore interface {
	ReadExtent(extent uint64) ([]byte, error)
	WriteExtent(extent uint64, plain []byte) error
}

type entry struct {
	extent    uint64
	data      []byte
	dirty     bool
	lastTouch time.Time
}

type WriteBack struct {
	mu         sync.Mutex
	capEntries int
	store      ExtentStore
	ll         *list.List
	byExtent   map[uint64]*list.Element
}

func New(store ExtentStore, capEntries int) *WriteBack {
	if capEntries < 8 {
		capEntries = 8
	}
	return &WriteBack{
		capEntries: capEntries,
		store:      store,
		ll:         list.New(),
		byExtent:   map[uint64]*list.Element{},
	}
}

func (w *WriteBack) Read(extent uint64) ([]byte, error) {
	w.mu.Lock()
	if el, ok := w.byExtent[extent]; ok {
		e := el.Value.(*entry)
		e.lastTouch = time.Now()
		w.ll.MoveToFront(el)
		data := append([]byte(nil), e.data...)
		w.mu.Unlock()
		return data, nil
	}
	w.mu.Unlock()

	data, err := w.store.ReadExtent(extent)
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.insertLocked(extent, data, false)
	return append([]byte(nil), data...), nil
}

func (w *WriteBack) Write(extent uint64, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.insertLocked(extent, append([]byte(nil), data...), true)
	return w.evictLocked()
}

func (w *WriteBack) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, el := range w.byExtent {
		e := el.Value.(*entry)
		if e.dirty {
			if err := w.store.WriteExtent(e.extent, e.data); err != nil {
				return err
			}
			e.dirty = false
		}
	}
	return nil
}

func (w *WriteBack) FlushExtent(extent uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	el, ok := w.byExtent[extent]
	if !ok {
		return nil
	}
	e := el.Value.(*entry)
	if !e.dirty {
		return nil
	}
	if err := w.store.WriteExtent(e.extent, e.data); err != nil {
		return err
	}
	e.dirty = false
	return nil
}

func (w *WriteBack) insertLocked(extent uint64, data []byte, dirty bool) {
	if el, ok := w.byExtent[extent]; ok {
		e := el.Value.(*entry)
		e.data = data
		e.dirty = e.dirty || dirty
		e.lastTouch = time.Now()
		w.ll.MoveToFront(el)
		return
	}
	el := w.ll.PushFront(&entry{extent: extent, data: data, dirty: dirty, lastTouch: time.Now()})
	w.byExtent[extent] = el
}

func (w *WriteBack) evictLocked() error {
	for len(w.byExtent) > w.capEntries {
		tail := w.ll.Back()
		if tail == nil {
			return errors.New("cache invariant broken")
		}
		e := tail.Value.(*entry)
		if e.dirty {
			if err := w.store.WriteExtent(e.extent, e.data); err != nil {
				return err
			}
		}
		delete(w.byExtent, e.extent)
		w.ll.Remove(tail)
	}
	return nil
}
