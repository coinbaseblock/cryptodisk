//go:build linux

package mount

import (
	"net"
	"os"
	"syscall"
)

// newUnixSocketPair creates a connected Unix domain socket pair suitable for
// passing one end to the kernel NBD driver via nbd-client. Unlike net.Pipe(),
// these are real kernel sockets with file descriptors that can be inherited by
// child processes.
func newUnixSocketPair() (userConn net.Conn, kernFile *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}

	userFile := os.NewFile(uintptr(fds[0]), "nbd-user")
	kernFile = os.NewFile(uintptr(fds[1]), "nbd-kern")

	userConn, err = net.FileConn(userFile)
	userFile.Close() // FileConn dups the fd, so close the original
	if err != nil {
		kernFile.Close()
		return nil, nil, err
	}

	return userConn, kernFile, nil
}
