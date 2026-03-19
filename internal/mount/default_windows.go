//go:build windows

package mount

import "sync"

var (
	defaultBridge     *WinSpdBridge
	defaultBridgeOnce sync.Once
)

func DefaultBackend() Backend {
	defaultBridgeOnce.Do(func() {
		defaultBridge = &WinSpdBridge{}
	})
	return defaultBridge
}
