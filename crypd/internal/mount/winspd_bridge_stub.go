//go:build !windows && !linux

package mount

func DefaultBackend() Backend { return stubBackend{} }

type stubBackend struct{}

func (stubBackend) CheckAvailable() error           { return ErrBackendMissing }
func (stubBackend) Mount(opts Options) error        { return ErrBackendMissing }
func (stubBackend) Unmount(mountPoint string) error { return ErrBackendMissing }
