//go:build linux

package mount

import "sync"

var (
	defaultNBD     *nbdBackend
	defaultNBDOnce sync.Once
)

func DefaultBackend() Backend {
	defaultNBDOnce.Do(func() {
		defaultNBD = newNBDBackend()
	})
	return defaultNBD
}
