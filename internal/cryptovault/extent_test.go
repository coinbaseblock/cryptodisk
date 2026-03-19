package cryptovault

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func makeTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecryptExtent_RoundTrip(t *testing.T) {
	key := makeTestKey(t)
	plain := make([]byte, 4096)
	for i := range plain {
		plain[i] = byte(i % 256)
	}

	ct, err := EncryptExtent(key, 0, plain)
	if err != nil {
		t.Fatal(err)
	}
	// Ciphertext should be plaintext + 16 bytes (Poly1305 tag)
	if len(ct) != len(plain)+16 {
		t.Errorf("ciphertext len = %d, want %d", len(ct), len(plain)+16)
	}

	got, err := DecryptExtent(key, 0, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("decrypted data doesn't match original")
	}
}

func TestEncryptExtent_DifferentIndexesDifferentCiphertext(t *testing.T) {
	key := makeTestKey(t)
	plain := make([]byte, 4096)

	ct0, _ := EncryptExtent(key, 0, plain)
	ct1, _ := EncryptExtent(key, 1, plain)

	if bytes.Equal(ct0, ct1) {
		t.Error("same plaintext at different extents should produce different ciphertext")
	}
}

func TestEncryptExtent_DifferentKeysDifferentCiphertext(t *testing.T) {
	key1 := makeTestKey(t)
	key2 := makeTestKey(t)
	plain := make([]byte, 4096)

	ct1, _ := EncryptExtent(key1, 0, plain)
	ct2, _ := EncryptExtent(key2, 0, plain)

	if bytes.Equal(ct1, ct2) {
		t.Error("same plaintext with different keys should produce different ciphertext")
	}
}

func TestDecryptExtent_WrongKey(t *testing.T) {
	key1 := makeTestKey(t)
	key2 := makeTestKey(t)
	plain := make([]byte, 4096)

	ct, _ := EncryptExtent(key1, 0, plain)
	_, err := DecryptExtent(key2, 0, ct)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestDecryptExtent_WrongIndex(t *testing.T) {
	key := makeTestKey(t)
	plain := make([]byte, 4096)

	ct, _ := EncryptExtent(key, 0, plain)
	_, err := DecryptExtent(key, 1, ct)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong extent index")
	}
}

func TestDecryptExtent_TamperedCiphertext(t *testing.T) {
	key := makeTestKey(t)
	plain := make([]byte, 4096)

	ct, _ := EncryptExtent(key, 0, plain)
	ct[100] ^= 0xFF // Flip a byte
	_, err := DecryptExtent(key, 0, ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestEncryptExtent_InvalidKeySize(t *testing.T) {
	_, err := EncryptExtent([]byte("short"), 0, make([]byte, 4096))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestDecryptExtent_InvalidKeySize(t *testing.T) {
	_, err := DecryptExtent([]byte("short"), 0, make([]byte, 4112))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestEncryptDecryptExtent_LargeExtent(t *testing.T) {
	key := makeTestKey(t)
	plain := make([]byte, 4*1024*1024) // 4MB extent
	rand.Read(plain)

	ct, err := EncryptExtent(key, 42, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptExtent(key, 42, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("large extent round-trip failed")
	}
}

func TestEncryptDecryptExtent_EmptyPlaintext(t *testing.T) {
	key := makeTestKey(t)
	plain := []byte{}

	ct, err := EncryptExtent(key, 0, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptExtent(key, 0, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Error("expected empty result for empty plaintext")
	}
}

func TestEncryptExtent_Deterministic(t *testing.T) {
	key := makeTestKey(t)
	plain := make([]byte, 4096)
	rand.Read(plain)

	// Same key, same index, same plaintext = same ciphertext (nonce is derived, not random)
	ct1, _ := EncryptExtent(key, 5, plain)
	ct2, _ := EncryptExtent(key, 5, plain)
	if !bytes.Equal(ct1, ct2) {
		t.Error("extent encryption should be deterministic for same key/index/plaintext")
	}
}

func TestPutLE64(t *testing.T) {
	tests := []struct {
		val  uint64
		want []byte
	}{
		{0, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{1, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{0x0102030405060708, []byte{8, 7, 6, 5, 4, 3, 2, 1}},
	}
	for _, tc := range tests {
		dst := make([]byte, 8)
		putLE64(dst, tc.val)
		if !bytes.Equal(dst, tc.want) {
			t.Errorf("putLE64(%d) = %v, want %v", tc.val, dst, tc.want)
		}
	}
}
