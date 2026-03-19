package cryptovault

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Magic                   = "ECDISK01"
	Version          uint32 = 1
	SaltSize                = 16
	NonceSize               = chacha20poly1305.NonceSizeX
	MasterKeySize           = 32
	HeaderSize              = 4096
	RecoveryKeyBytes        = 20
)

type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

type Header struct {
	Magic            [8]byte
	Version          uint32
	HeaderSize       uint32
	Salt             [SaltSize]byte
	Nonce            [NonceSize]byte
	KDF              KDFParams
	WrappedMasterKey []byte

	RecoveryNonce            [NonceSize]byte
	WrappedMasterKeyRecovery []byte

	DiskSizeBytes uint64
	ExtentSize    uint32
	Flags         uint32
}

type UnlockBundle struct {
	Header    *Header
	MasterKey []byte
}

func DefaultKDF() KDFParams {
	return KDFParams{
		Time:    3,
		Memory:  256 * 1024,
		Threads: 4,
		KeyLen:  32,
	}
}

func NewHeader(password string, diskSizeBytes uint64, extentSize uint32) (*Header, string, []byte, error) {
	if password == "" {
		return nil, "", nil, errors.New("password is required")
	}
	masterKey := make([]byte, MasterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, "", nil, err
	}
	recoveryKeyRaw := make([]byte, RecoveryKeyBytes)
	if _, err := rand.Read(recoveryKeyRaw); err != nil {
		return nil, "", nil, err
	}
	recoveryKey := formatRecoveryKey(recoveryKeyRaw)
	hdr, err := WrapHeader(password, recoveryKey, masterKey, diskSizeBytes, extentSize)
	if err != nil {
		return nil, "", nil, err
	}
	return hdr, recoveryKey, masterKey, nil
}

func WrapHeader(password, recoveryKey string, masterKey []byte, diskSizeBytes uint64, extentSize uint32) (*Header, error) {
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("master key must be %d bytes", MasterKeySize)
	}
	var hdr Header
	copy(hdr.Magic[:], []byte(Magic))
	hdr.Version = Version
	hdr.HeaderSize = HeaderSize
	hdr.KDF = DefaultKDF()
	hdr.DiskSizeBytes = diskSizeBytes
	hdr.ExtentSize = extentSize
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(hdr.Nonce[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(hdr.RecoveryNonce[:]); err != nil {
		return nil, err
	}

	kek := argon2.IDKey([]byte(password), hdr.Salt[:], hdr.KDF.Time, hdr.KDF.Memory, hdr.KDF.Threads, hdr.KDF.KeyLen)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	aad := buildAAD(&hdr)
	hdr.WrappedMasterKey = aead.Seal(nil, hdr.Nonce[:], masterKey, aad)

	rSalt := recoverySalt(hdr.Salt[:])
	rkek := argon2.IDKey([]byte(normalizeRecoveryKey(recoveryKey)), rSalt, 2, 64*1024, 2, 32)
	raead, err := chacha20poly1305.NewX(rkek)
	if err != nil {
		return nil, err
	}
	hdr.WrappedMasterKeyRecovery = raead.Seal(nil, hdr.RecoveryNonce[:], masterKey, aad)
	return &hdr, nil
}

func UnlockWithPassword(hdr *Header, password string) (*UnlockBundle, error) {
	kek := argon2.IDKey([]byte(password), hdr.Salt[:], hdr.KDF.Time, hdr.KDF.Memory, hdr.KDF.Threads, hdr.KDF.KeyLen)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	mk, err := aead.Open(nil, hdr.Nonce[:], hdr.WrappedMasterKey, buildAAD(hdr))
	if err != nil {
		return nil, errors.New("invalid password or damaged header")
	}
	return &UnlockBundle{Header: hdr, MasterKey: mk}, nil
}

func UnlockWithRecovery(hdr *Header, recoveryKey string) (*UnlockBundle, error) {
	rSalt := recoverySalt(hdr.Salt[:])
	rkek := argon2.IDKey([]byte(normalizeRecoveryKey(recoveryKey)), rSalt, 2, 64*1024, 2, 32)
	raead, err := chacha20poly1305.NewX(rkek)
	if err != nil {
		return nil, err
	}
	mk, err := raead.Open(nil, hdr.RecoveryNonce[:], hdr.WrappedMasterKeyRecovery, buildAAD(hdr))
	if err != nil {
		return nil, errors.New("invalid recovery key or damaged header")
	}
	return &UnlockBundle{Header: hdr, MasterKey: mk}, nil
}

func RewrapPassword(hdr *Header, masterKey []byte, newPassword string) error {
	if newPassword == "" {
		return errors.New("new password is required")
	}
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return err
	}
	if _, err := rand.Read(hdr.Nonce[:]); err != nil {
		return err
	}
	hdr.KDF = DefaultKDF()
	kek := argon2.IDKey([]byte(newPassword), hdr.Salt[:], hdr.KDF.Time, hdr.KDF.Memory, hdr.KDF.Threads, hdr.KDF.KeyLen)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return err
	}
	hdr.WrappedMasterKey = aead.Seal(nil, hdr.Nonce[:], masterKey, buildAAD(hdr))
	return nil
}

func SerializeHeader(w io.Writer, hdr *Header) error {
	if hdr.HeaderSize != HeaderSize {
		return fmt.Errorf("unexpected header size %d", hdr.HeaderSize)
	}
	buf := make([]byte, HeaderSize)
	off := 0
	copy(buf[off:off+8], hdr.Magic[:])
	off += 8
	binary.LittleEndian.PutUint32(buf[off:off+4], hdr.Version)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:off+4], hdr.HeaderSize)
	off += 4
	copy(buf[off:off+SaltSize], hdr.Salt[:])
	off += SaltSize
	copy(buf[off:off+NonceSize], hdr.Nonce[:])
	off += NonceSize
	binary.LittleEndian.PutUint32(buf[off:off+4], hdr.KDF.Time)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:off+4], hdr.KDF.Memory)
	off += 4
	buf[off] = hdr.KDF.Threads
	off++
	binary.LittleEndian.PutUint32(buf[off:off+4], hdr.KDF.KeyLen)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:off+4], uint32(len(hdr.WrappedMasterKey)))
	off += 4
	copy(buf[off:off+len(hdr.WrappedMasterKey)], hdr.WrappedMasterKey)
	off += len(hdr.WrappedMasterKey)
	copy(buf[off:off+NonceSize], hdr.RecoveryNonce[:])
	off += NonceSize
	binary.LittleEndian.PutUint32(buf[off:off+4], uint32(len(hdr.WrappedMasterKeyRecovery)))
	off += 4
	copy(buf[off:off+len(hdr.WrappedMasterKeyRecovery)], hdr.WrappedMasterKeyRecovery)
	off += len(hdr.WrappedMasterKeyRecovery)
	binary.LittleEndian.PutUint64(buf[off:off+8], hdr.DiskSizeBytes)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:off+4], hdr.ExtentSize)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:off+4], hdr.Flags)
	off += 4
	_, err := w.Write(buf)
	return err
}

func ParseHeader(r io.Reader) (*Header, error) {
	buf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	off := 0
	var hdr Header
	copy(hdr.Magic[:], buf[off:off+8])
	off += 8
	if string(hdr.Magic[:]) != Magic {
		return nil, errors.New("invalid container magic")
	}
	hdr.Version = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	hdr.HeaderSize = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	copy(hdr.Salt[:], buf[off:off+SaltSize])
	off += SaltSize
	copy(hdr.Nonce[:], buf[off:off+NonceSize])
	off += NonceSize
	hdr.KDF.Time = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	hdr.KDF.Memory = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	hdr.KDF.Threads = buf[off]
	off++
	hdr.KDF.KeyLen = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	wmLen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
	off += 4
	hdr.WrappedMasterKey = append([]byte(nil), buf[off:off+wmLen]...)
	off += wmLen
	copy(hdr.RecoveryNonce[:], buf[off:off+NonceSize])
	off += NonceSize
	wrLen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
	off += 4
	hdr.WrappedMasterKeyRecovery = append([]byte(nil), buf[off:off+wrLen]...)
	off += wrLen
	hdr.DiskSizeBytes = binary.LittleEndian.Uint64(buf[off : off+8])
	off += 8
	hdr.ExtentSize = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	hdr.Flags = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	return &hdr, nil
}

func BuildExtentNonce(extent uint64, baseKey []byte) [NonceSize]byte {
	var n [NonceSize]byte
	copy(n[:16], baseKey[:16])
	binary.LittleEndian.PutUint64(n[16:24], extent)
	return n
}

func buildAAD(h *Header) []byte {
	aad := make([]byte, 0, 8+4+8+4)
	aad = append(aad, h.Magic[:]...)
	tmp4 := make([]byte, 4)
	tmp8 := make([]byte, 8)
	binary.LittleEndian.PutUint32(tmp4, h.Version)
	aad = append(aad, tmp4...)
	binary.LittleEndian.PutUint64(tmp8, h.DiskSizeBytes)
	aad = append(aad, tmp8...)
	binary.LittleEndian.PutUint32(tmp4, h.ExtentSize)
	aad = append(aad, tmp4...)
	return aad
}

func recoverySalt(salt []byte) []byte {
	out := make([]byte, len(salt)+4)
	copy(out, salt)
	copy(out[len(salt):], []byte("reco"))
	return out
}

func formatRecoveryKey(raw []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	enc = strings.ToUpper(enc)
	groups := make([]string, 0, (len(enc)+3)/4)
	for i := 0; i < len(enc); i += 4 {
		end := i + 4
		if end > len(enc) {
			end = len(enc)
		}
		groups = append(groups, enc[i:end])
	}
	return strings.Join(groups, "-")
}

func normalizeRecoveryKey(s string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(s)), "-", "")
}
