//go:build !windows

package mount

func DefaultBackend() Backend { return stubBackend{} }

type stubBackend struct{}

func (stubBackend) Mount(opts Options) error        { return ErrBackendMissing }
func (stubBackend) Unmount(mountPoint string) error { return ErrBackendMissing }
