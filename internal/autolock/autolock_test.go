package autolock

import (
	"sync"
	"testing"
	"time"
)

type mockLocker struct {
	mu       sync.Mutex
	locked   bool
	reason   string
	lockErr  error
}

func (m *mockLocker) LockNow(reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locked = true
	m.reason = reason
	return m.lockErr
}

func (m *mockLocker) isLocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.locked
}

func (m *mockLocker) getReason() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reason
}

func TestNew(t *testing.T) {
	l := &mockLocker{}
	m := New(l, 5*time.Second)
	if m == nil {
		t.Fatal("New returned nil")
	}
	if m.idleFor != 5*time.Second {
		t.Errorf("idleFor = %v, want 5s", m.idleFor)
	}
}

func TestTouch_ResetsTimer(t *testing.T) {
	l := &mockLocker{}
	m := New(l, 100*time.Millisecond)

	go m.Run(20 * time.Millisecond)
	defer m.Stop()

	// Keep touching to prevent lock
	for i := 0; i < 10; i++ {
		time.Sleep(30 * time.Millisecond)
		m.Touch()
	}

	if l.isLocked() {
		t.Error("should not be locked while being touched")
	}
}

func TestIdleTimeout_LocksWhenIdle(t *testing.T) {
	l := &mockLocker{}
	m := New(l, 50*time.Millisecond)

	go m.Run(10 * time.Millisecond)

	// Wait for idle timeout
	time.Sleep(200 * time.Millisecond)

	if !l.isLocked() {
		t.Error("should be locked after idle timeout")
	}
	if l.getReason() != "idle timeout" {
		t.Errorf("reason = %q, want %q", l.getReason(), "idle timeout")
	}
}

func TestStop_PreventsLock(t *testing.T) {
	l := &mockLocker{}
	m := New(l, 50*time.Millisecond)

	go m.Run(10 * time.Millisecond)
	m.Stop()

	time.Sleep(200 * time.Millisecond)

	if l.isLocked() {
		t.Error("should not be locked after Stop")
	}
}

func TestMultipleTouch(t *testing.T) {
	l := &mockLocker{}
	m := New(l, 200*time.Millisecond)

	go m.Run(50 * time.Millisecond)
	defer m.Stop()

	// Multiple rapid touches should be fine
	for i := 0; i < 5; i++ {
		m.Touch()
	}

	if l.isLocked() {
		t.Error("should not be locked immediately after touches")
	}
}
