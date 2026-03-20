package cryptovault

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptExtent(masterKey []byte, extentIndex uint64, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}
	nonce := BuildExtentNonce(extentIndex, masterKey)
	aad := make([]byte, 8)
	putLE64(aad, extentIndex)
	return aead.Seal(nil, nonce[:], plain, aad), nil
}

func DecryptExtent(masterKey []byte, extentIndex uint64, cipherText []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}
	nonce := BuildExtentNonce(extentIndex, masterKey)
	aad := make([]byte, 8)
	putLE64(aad, extentIndex)
	out, err := aead.Open(nil, nonce[:], cipherText, aad)
	if err != nil {
		return nil, fmt.Errorf("extent %d failed authentication: %w", extentIndex, err)
	}
	return out, nil
}

func putLE64(dst []byte, v uint64) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
	dst[4] = byte(v >> 32)
	dst[5] = byte(v >> 40)
	dst[6] = byte(v >> 48)
	dst[7] = byte(v >> 56)
}
