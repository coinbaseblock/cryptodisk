package app

import "os"

// openFile opens a file for reading (helper for GUI actions).
func openFile(path string) (*os.File, error) {
	return os.Open(path)
}
