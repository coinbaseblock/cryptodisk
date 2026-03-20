//go:build linux

package mount

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"crypd/internal/autolock"
)

// NBD protocol constants
const (
	nbdRequestMagic  = 0x25609513
	nbdResponseMagic = 0x67446698

	nbdCmdRead  = 0
	nbdCmdWrite = 1
	nbdCmdDisc  = 2
	nbdCmdFlush = 3
	nbdCmdTrim  = 4
)

// nbdRequest is the wire format of an NBD request (28 bytes).
type nbdRequest struct {
	Magic  uint32
	Type   uint32
	Handle uint64
	Offset uint64
	Length uint32
}

// nbdResponse is the wire format of an NBD response (16 bytes).
type nbdResponse struct {
	Magic  uint32
	Error  uint32
	Handle uint64
}

// nbdBackend exposes an encrypted container as a Linux block device via NBD.
type nbdBackend struct {
	mu     sync.Mutex
	mounts map[string]*nbdSession
}

type nbdSession struct {
	dev    string
	conn   net.Conn
	bd     *BlockDev
	stop   chan struct{}
	locker *autolock.Manager
}

func newNBDBackend() *nbdBackend {
	return &nbdBackend{
		mounts: make(map[string]*nbdSession),
	}
}

func (b *nbdBackend) CheckAvailable() error {
	if _, err := exec.LookPath("nbd-client"); err != nil {
		return fmt.Errorf("%w — nbd-client not found on PATH; install nbd-client (e.g. apt install nbd-client) and ensure the nbd kernel module is loaded (modprobe nbd)", ErrBackendMissing)
	}
	return nil
}

func (b *nbdBackend) Mount(opts Options) error {
	if opts.Store == nil {
		return fmt.Errorf("mount: extent store is required")
	}
	if opts.MountPoint == "" {
		return fmt.Errorf("mount: mount point is required")
	}

	bd := NewBlockDev(opts.Store, opts.DiskSizeBytes, opts.ExtentSize)

	// Create a Unix socket pair for the NBD kernel driver.
	// We need real Unix domain sockets (not net.Pipe) because nbd-client
	// requires a kernel file descriptor it can hand to the NBD driver.
	userConn, kernFile, err := newUnixSocketPair()
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}

	dev := opts.MountPoint

	cmd := exec.Command("nbd-client", "-b", "512",
		"-s", fmt.Sprintf("%d", bd.DiskSizeBytes()/512),
		"-u", fmt.Sprintf("/dev/fd/%d", 3),
		dev)
	cmd.ExtraFiles = []*os.File{kernFile}
	if err := cmd.Start(); err != nil {
		userConn.Close()
		kernFile.Close()
		return fmt.Errorf("nbd-client: %w", err)
	}
	kernFile.Close()

	sess := &nbdSession{
		dev:  dev,
		conn: userConn,
		bd:   bd,
		stop: make(chan struct{}),
	}

	// Set up auto-lock if configured
	if opts.IdleSeconds > 0 {
		sess.locker = autolock.New(sess, time.Duration(opts.IdleSeconds)*time.Second)
		go sess.locker.Run(5 * time.Second)
	}

	b.mu.Lock()
	b.mounts[dev] = sess
	b.mu.Unlock()

	// Serve NBD requests in the background
	go sess.serve()

	return nil
}

func (b *nbdBackend) Unmount(mountPoint string) error {
	b.mu.Lock()
	sess, ok := b.mounts[mountPoint]
	if !ok {
		b.mu.Unlock()
		return fmt.Errorf("no active mount at %s", mountPoint)
	}
	delete(b.mounts, mountPoint)
	b.mu.Unlock()

	return sess.shutdown()
}

func (sess *nbdSession) serve() {
	defer sess.conn.Close()

	for {
		select {
		case <-sess.stop:
			return
		default:
		}

		var req nbdRequest
		if err := binary.Read(sess.conn, binary.BigEndian, &req); err != nil {
			return
		}
		if req.Magic != nbdRequestMagic {
			return
		}

		resp := nbdResponse{
			Magic:  nbdResponseMagic,
			Handle: req.Handle,
		}

		switch req.Type {
		case nbdCmdRead:
			if sess.locker != nil {
				sess.locker.Touch()
			}
			buf := make([]byte, req.Length)
			if _, err := sess.bd.ReadAt(buf, int64(req.Offset)); err != nil {
				resp.Error = 5 // EIO
			}
			if err := binary.Write(sess.conn, binary.BigEndian, resp); err != nil {
				return
			}
			// NBD protocol requires sending Length bytes after the response
			// header for reads, regardless of error status.
			if _, err := sess.conn.Write(buf); err != nil {
				return
			}

		case nbdCmdWrite:
			if sess.locker != nil {
				sess.locker.Touch()
			}
			buf := make([]byte, req.Length)
			if _, err := io.ReadFull(sess.conn, buf); err != nil {
				return
			}
			if _, err := sess.bd.WriteAt(buf, int64(req.Offset)); err != nil {
				resp.Error = 5 // EIO
			}
			if err := binary.Write(sess.conn, binary.BigEndian, resp); err != nil {
				return
			}

		case nbdCmdFlush:
			if err := sess.bd.Flush(); err != nil {
				resp.Error = 5
			}
			if err := binary.Write(sess.conn, binary.BigEndian, resp); err != nil {
				return
			}

		case nbdCmdDisc:
			sess.bd.Flush()
			binary.Write(sess.conn, binary.BigEndian, resp)
			return

		case nbdCmdTrim:
			// No-op for encrypted containers
			if err := binary.Write(sess.conn, binary.BigEndian, resp); err != nil {
				return
			}

		default:
			resp.Error = 22 // EINVAL
			if err := binary.Write(sess.conn, binary.BigEndian, resp); err != nil {
				return
			}
		}
	}
}

func (sess *nbdSession) shutdown() error {
	close(sess.stop)
	if sess.locker != nil {
		sess.locker.Stop()
	}
	sess.bd.Flush()
	sess.conn.Close()
	// Disconnect the NBD device
	exec.Command("nbd-client", "-d", sess.dev).Run()
	return nil
}

// LockNow implements autolock.Locker.
func (sess *nbdSession) LockNow(reason string) error {
	return sess.shutdown()
}
