package mount

import "errors"

type Options struct {
	ContainerPath string
	MountPoint    string
	IdleSeconds   int
	CacheExtents  int
}

var ErrBackendMissing = errors.New("no block-device backend installed")

type Backend interface {
	Mount(opts Options) error
	Unmount(mountPoint string) error
}
