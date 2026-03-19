//go:build windows

package mount

type WinSpdBridge struct{}

func (b WinSpdBridge) Mount(opts Options) error {
	return ErrBackendMissing
}

func (b WinSpdBridge) Unmount(mountPoint string) error {
	return ErrBackendMissing
}
