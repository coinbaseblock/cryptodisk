//go:build linux

package mount

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestNBDBackend_CheckAvailable(t *testing.T) {
	b := newNBDBackend()
	err := b.CheckAvailable()
	// On systems without nbd-client, this should return ErrBackendMissing.
	// On systems with nbd-client, it should return nil.
	if err != nil && !errors.Is(err, ErrBackendMissing) {
		t.Fatalf("CheckAvailable returned unexpected error type: %v", err)
	}
}

func TestNBDBackend_MountNilStore(t *testing.T) {
	b := newNBDBackend()
	err := b.Mount(Options{MountPoint: "/dev/nbd0"})
	if err == nil {
		t.Fatal("expected error when store is nil")
	}
}

func TestNBDBackend_MountEmptyMountPoint(t *testing.T) {
	b := newNBDBackend()
	store := newMemExtentStore(4096)
	err := b.Mount(Options{Store: store})
	if err == nil {
		t.Fatal("expected error when mount point is empty")
	}
}

func TestNBDBackend_UnmountNotMounted(t *testing.T) {
	b := newNBDBackend()
	err := b.Unmount("/dev/nbd99")
	if err == nil {
		t.Fatal("expected error when unmounting non-existent device")
	}
}

func TestNBDServe_ReadProtocol(t *testing.T) {
	// Test that the serve loop correctly handles a read request and sends
	// response header + data bytes per the NBD protocol.
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	// Write known data into extent 0
	data := make([]byte, 4096)
	for i := range data {
		data[i] = 0xAA
	}
	bd.WriteAt(data, 0)

	client, server := net.Pipe()
	sess := &nbdSession{
		dev:  "/dev/nbd99",
		conn: server,
		bd:   bd,
		stop: make(chan struct{}),
	}
	go sess.serve()

	// Send a read request for 512 bytes at offset 0
	req := nbdRequest{
		Magic:  nbdRequestMagic,
		Type:   nbdCmdRead,
		Handle: 42,
		Offset: 0,
		Length: 512,
	}
	if err := binary.Write(client, binary.BigEndian, req); err != nil {
		t.Fatal(err)
	}

	// Read the response header
	var resp nbdResponse
	if err := binary.Read(client, binary.BigEndian, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Magic != nbdResponseMagic {
		t.Fatalf("response magic = %#x, want %#x", resp.Magic, nbdResponseMagic)
	}
	if resp.Handle != 42 {
		t.Fatalf("response handle = %d, want 42", resp.Handle)
	}
	if resp.Error != 0 {
		t.Fatalf("response error = %d, want 0", resp.Error)
	}

	// Read the data payload
	readBuf := make([]byte, 512)
	if _, err := client.Read(readBuf); err != nil {
		t.Fatal(err)
	}
	for i, b := range readBuf {
		if b != 0xAA {
			t.Fatalf("byte %d = %#x, want 0xAA", i, b)
		}
	}

	// Send disconnect to clean up
	disc := nbdRequest{Magic: nbdRequestMagic, Type: nbdCmdDisc, Handle: 1}
	binary.Write(client, binary.BigEndian, disc)
	client.Close()
}

func TestNBDServe_WriteProtocol(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	client, server := net.Pipe()
	sess := &nbdSession{
		dev:  "/dev/nbd99",
		conn: server,
		bd:   bd,
		stop: make(chan struct{}),
	}
	go sess.serve()

	// Send a write request for 512 bytes at offset 0
	writeData := make([]byte, 512)
	for i := range writeData {
		writeData[i] = 0xBB
	}

	req := nbdRequest{
		Magic:  nbdRequestMagic,
		Type:   nbdCmdWrite,
		Handle: 7,
		Offset: 0,
		Length: 512,
	}
	if err := binary.Write(client, binary.BigEndian, req); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(writeData); err != nil {
		t.Fatal(err)
	}

	// Read the write response (no data payload)
	var resp nbdResponse
	if err := binary.Read(client, binary.BigEndian, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != 0 {
		t.Fatalf("write response error = %d, want 0", resp.Error)
	}
	if resp.Handle != 7 {
		t.Fatalf("response handle = %d, want 7", resp.Handle)
	}

	// Verify data was written by reading it back through the protocol
	readReq := nbdRequest{
		Magic:  nbdRequestMagic,
		Type:   nbdCmdRead,
		Handle: 8,
		Offset: 0,
		Length: 512,
	}
	binary.Write(client, binary.BigEndian, readReq)

	var readResp nbdResponse
	binary.Read(client, binary.BigEndian, &readResp)
	if readResp.Error != 0 {
		t.Fatalf("read-back error = %d", readResp.Error)
	}

	readBuf := make([]byte, 512)
	client.Read(readBuf)
	for i, b := range readBuf {
		if b != 0xBB {
			t.Fatalf("read-back byte %d = %#x, want 0xBB", i, b)
		}
	}

	disc := nbdRequest{Magic: nbdRequestMagic, Type: nbdCmdDisc}
	binary.Write(client, binary.BigEndian, disc)
	client.Close()
}

func TestNBDServe_FlushProtocol(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	client, server := net.Pipe()
	sess := &nbdSession{
		dev:  "/dev/nbd99",
		conn: server,
		bd:   bd,
		stop: make(chan struct{}),
	}
	go sess.serve()

	req := nbdRequest{
		Magic:  nbdRequestMagic,
		Type:   nbdCmdFlush,
		Handle: 99,
	}
	binary.Write(client, binary.BigEndian, req)

	var resp nbdResponse
	if err := binary.Read(client, binary.BigEndian, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != 0 {
		t.Fatalf("flush error = %d, want 0", resp.Error)
	}
	if resp.Handle != 99 {
		t.Fatalf("handle = %d, want 99", resp.Handle)
	}

	disc := nbdRequest{Magic: nbdRequestMagic, Type: nbdCmdDisc}
	binary.Write(client, binary.BigEndian, disc)
	client.Close()
}

func TestNBDServe_BadMagic(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	client, server := net.Pipe()
	sess := &nbdSession{
		dev:  "/dev/nbd99",
		conn: server,
		bd:   bd,
		stop: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		sess.serve()
		close(done)
	}()

	// Send a request with bad magic — serve should exit
	req := nbdRequest{
		Magic: 0xDEADBEEF,
		Type:  nbdCmdRead,
	}
	binary.Write(client, binary.BigEndian, req)
	client.Close()

	<-done // serve should have returned
}

func TestNBDServe_DisconnectClean(t *testing.T) {
	store := newMemExtentStore(4096)
	bd := NewBlockDev(store, 4096*10, 4096)

	client, server := net.Pipe()
	sess := &nbdSession{
		dev:  "/dev/nbd99",
		conn: server,
		bd:   bd,
		stop: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		sess.serve()
		close(done)
	}()

	req := nbdRequest{Magic: nbdRequestMagic, Type: nbdCmdDisc, Handle: 1}
	binary.Write(client, binary.BigEndian, req)

	// Read the disconnect response
	var resp nbdResponse
	binary.Read(client, binary.BigEndian, &resp)
	if resp.Handle != 1 {
		t.Fatalf("disc handle = %d, want 1", resp.Handle)
	}

	client.Close()
	<-done
}

func TestNewUnixSocketPair(t *testing.T) {
	userConn, kernFile, err := newUnixSocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer userConn.Close()
	defer kernFile.Close()

	// Verify the kernel file has a valid fd
	if kernFile.Fd() == ^uintptr(0) {
		t.Fatal("kernel file has invalid fd")
	}
}
