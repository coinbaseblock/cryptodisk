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

	"ecdisk/internal/autolock"
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

	// Create a Unix socket pair for the NBD kernel driver
	fds, err := newSocketPair()
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	userConn := fds[0]
	kernConn := fds[1]

	dev := opts.MountPoint

	// Configure the NBD device via nbd-client or ioctl
	// For simplicity, we use the socket-based approach with nbd-client
	kernFile, err := kernConn.(*net.UnixConn).File()
	if err != nil {
		userConn.Close()
		kernConn.Close()
		return fmt.Errorf("get kernel fd: %w", err)
	}

	cmd := exec.Command("nbd-client", "-b", "512",
		"-s", fmt.Sprintf("%d", bd.DiskSizeBytes()/512),
		"-u", kernFile.Name(),
		dev)
	cmd.ExtraFiles = []*os.File{kernFile}
	if err := cmd.Start(); err != nil {
		userConn.Close()
		kernConn.Close()
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
			if err == io.EOF {
				return
			}
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
			binary.Write(sess.conn, binary.BigEndian, resp)
			if resp.Error == 0 {
				sess.conn.Write(buf)
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
			binary.Write(sess.conn, binary.BigEndian, resp)

		case nbdCmdFlush:
			if err := sess.bd.Flush(); err != nil {
				resp.Error = 5
			}
			binary.Write(sess.conn, binary.BigEndian, resp)

		case nbdCmdDisc:
			sess.bd.Flush()
			binary.Write(sess.conn, binary.BigEndian, resp)
			return

		case nbdCmdTrim:
			// No-op for encrypted containers
			binary.Write(sess.conn, binary.BigEndian, resp)

		default:
			resp.Error = 22 // EINVAL
			binary.Write(sess.conn, binary.BigEndian, resp)
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

func newSocketPair() ([2]net.Conn, error) {
	c1, c2 := net.Pipe()
	return [2]net.Conn{c1, c2}, nil
}
