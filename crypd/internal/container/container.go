package container

import (
	"errors"
	"fmt"
	"io"
	"os"

	"crypd/internal/cryptovault"
)

type Handle struct {
	File      *os.File
	Header    *cryptovault.Header
	MasterKey []byte
}

func Create(path, password string, diskSizeBytes uint64, extentSize uint32) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("file already exists: %s", path)
	}
	hdr, recoveryKey, _, err := cryptovault.NewHeader(password, diskSizeBytes, extentSize)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := cryptovault.SerializeHeader(f, hdr); err != nil {
		return "", err
	}
	// Allocate logical payload size to make future block mapping deterministic.
	payloadSize := payloadLength(diskSizeBytes, extentSize)
	if err := f.Truncate(int64(cryptovault.HeaderSize) + int64(payloadSize)); err != nil {
		return "", err
	}
	return recoveryKey, nil
}

func OpenWithPassword(path, password string) (*Handle, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	hdr, err := cryptovault.ParseHeader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ub, err := cryptovault.UnlockWithPassword(hdr, password)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Handle{File: f, Header: ub.Header, MasterKey: ub.MasterKey}, nil
}

func OpenWithRecovery(path, recoveryKey string) (*Handle, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	hdr, err := cryptovault.ParseHeader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ub, err := cryptovault.UnlockWithRecovery(hdr, recoveryKey)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Handle{File: f, Header: ub.Header, MasterKey: ub.MasterKey}, nil
}

func (h *Handle) Close() error {
	if h == nil || h.File == nil {
		return nil
	}
	zero(h.MasterKey)
	err := h.File.Close()
	h.File = nil
	return err
}

func (h *Handle) ChangePassword(newPassword string) error {
	if err := cryptovault.RewrapPassword(h.Header, h.MasterKey, newPassword); err != nil {
		return err
	}
	if _, err := h.File.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := cryptovault.SerializeHeader(h.File, h.Header); err != nil {
		return err
	}
	return h.File.Sync()
}

func (h *Handle) ReadExtent(extentIndex uint64) ([]byte, error) {
	extentSize := int(h.Header.ExtentSize)
	buf := make([]byte, extentSize+16)
	off := int64(cryptovault.HeaderSize) + int64(extentIndex)*int64(extentSize+16)
	if _, err := h.File.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	isZero := true
	for _, b := range buf {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return make([]byte, extentSize), nil
	}
	plain, err := cryptovault.DecryptExtent(h.MasterKey, extentIndex, buf)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func (h *Handle) WriteExtent(extentIndex uint64, plain []byte) error {
	if len(plain) != int(h.Header.ExtentSize) {
		return fmt.Errorf("extent size mismatch: got %d want %d", len(plain), h.Header.ExtentSize)
	}
	cipherText, err := cryptovault.EncryptExtent(h.MasterKey, extentIndex, plain)
	if err != nil {
		return err
	}
	off := int64(cryptovault.HeaderSize) + int64(extentIndex)*int64(len(cipherText))
	if _, err := h.File.WriteAt(cipherText, off); err != nil {
		return err
	}
	return nil
}

func payloadLength(diskSizeBytes uint64, extentSize uint32) uint64 {
	n := diskSizeBytes / uint64(extentSize)
	if diskSizeBytes%uint64(extentSize) != 0 {
		n++
	}
	return n * uint64(extentSize+16)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
