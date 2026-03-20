//go:build !windows

package app

import "errors"

func backendRepairMenuSuffix() string {
	return ""
}

func cmdBackendDoctor(args []string) error {
	return errors.New("backend diagnostics are only available on Windows")
}

func cmdRepairBackend(args []string) error {
	return errors.New("backend repair is only available on Windows")
}
