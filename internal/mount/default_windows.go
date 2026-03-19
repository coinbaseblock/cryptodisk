//go:build windows

package mount

func DefaultBackend() Backend {
	return &WinSpdBridge{}
}
