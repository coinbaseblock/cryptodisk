package autolock

import (
	"sync"
	"time"
)

type Locker interface {
	LockNow(reason string) error
}

type Manager struct {
	mu       sync.Mutex
	idleFor  time.Duration
	lastSeen time.Time
	locker   Locker
	stopped  chan struct{}
}

func New(locker Locker, idleFor time.Duration) *Manager {
	return &Manager{
		idleFor:  idleFor,
		lastSeen: time.Now(),
		locker:   locker,
		stopped:  make(chan struct{}),
	}
}

func (m *Manager) Touch() {
	m.mu.Lock()
	m.lastSeen = time.Now()
	m.mu.Unlock()
}

func (m *Manager) Run(pollEvery time.Duration) {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.mu.Lock()
			idle := time.Since(m.lastSeen)
			m.mu.Unlock()
			if idle >= m.idleFor {
				_ = m.locker.LockNow("idle timeout")
				return
			}
		case <-m.stopped:
			return
		}
	}
}

func (m *Manager) Stop() {
	close(m.stopped)
}
