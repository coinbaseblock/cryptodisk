package cryptovault

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestNewHeader_Basic(t *testing.T) {
	hdr, recoveryKey, masterKey, err := NewHeader("testpassword", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if string(hdr.Magic[:]) != Magic {
		t.Errorf("magic = %q, want %q", hdr.Magic[:], Magic)
	}
	if hdr.Version != Version {
		t.Errorf("version = %d, want %d", hdr.Version, Version)
	}
	if hdr.HeaderSize != HeaderSize {
		t.Errorf("header size = %d, want %d", hdr.HeaderSize, HeaderSize)
	}
	if hdr.DiskSizeBytes != 1<<30 {
		t.Errorf("disk size = %d, want %d", hdr.DiskSizeBytes, 1<<30)
	}
	if hdr.ExtentSize != 4096 {
		t.Errorf("extent size = %d, want %d", hdr.ExtentSize, 4096)
	}
	if len(masterKey) != MasterKeySize {
		t.Errorf("master key len = %d, want %d", len(masterKey), MasterKeySize)
	}
	if recoveryKey == "" {
		t.Error("recovery key is empty")
	}
	if len(hdr.WrappedMasterKey) != MasterKeySize+16 {
		t.Errorf("wrapped master key len = %d, want %d", len(hdr.WrappedMasterKey), MasterKeySize+16)
	}
	if len(hdr.WrappedMasterKeyRecovery) != MasterKeySize+16 {
		t.Errorf("wrapped recovery key len = %d, want %d", len(hdr.WrappedMasterKeyRecovery), MasterKeySize+16)
	}
}

func TestNewHeader_EmptyPassword(t *testing.T) {
	_, _, _, err := NewHeader("", 1<<30, 4096)
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestRecoveryKeyFormat(t *testing.T) {
	raw := make([]byte, RecoveryKeyBytes)
	for i := range raw {
		raw[i] = byte(i)
	}
	key := formatRecoveryKey(raw)
	// Should be groups of 4 uppercase base32 chars separated by dashes
	parts := strings.Split(key, "-")
	for i, p := range parts {
		if i < len(parts)-1 && len(p) != 4 {
			t.Errorf("group %d has len %d, want 4", i, len(p))
		}
		if strings.ToUpper(p) != p {
			t.Errorf("group %d is not uppercase: %q", i, p)
		}
	}
}

func TestNormalizeRecoveryKey(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"ABCD-EFGH", "ABCDEFGH"},
		{"abcd-efgh", "ABCDEFGH"},
		{" abcd-efgh ", "ABCDEFGH"},
	}
	for _, tc := range tests {
		got := normalizeRecoveryKey(tc.input)
		if got != tc.want {
			t.Errorf("normalizeRecoveryKey(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSerializeParseRoundTrip(t *testing.T) {
	hdr, _, _, err := NewHeader("password123", 2<<30, 8192)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := SerializeHeader(&buf, hdr); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != HeaderSize {
		t.Fatalf("serialized size = %d, want %d", buf.Len(), HeaderSize)
	}

	parsed, err := ParseHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if string(parsed.Magic[:]) != string(hdr.Magic[:]) {
		t.Error("magic mismatch")
	}
	if parsed.Version != hdr.Version {
		t.Error("version mismatch")
	}
	if parsed.HeaderSize != hdr.HeaderSize {
		t.Error("header size mismatch")
	}
	if parsed.Salt != hdr.Salt {
		t.Error("salt mismatch")
	}
	if parsed.Nonce != hdr.Nonce {
		t.Error("nonce mismatch")
	}
	if parsed.KDF != hdr.KDF {
		t.Error("KDF mismatch")
	}
	if !bytes.Equal(parsed.WrappedMasterKey, hdr.WrappedMasterKey) {
		t.Error("wrapped master key mismatch")
	}
	if parsed.RecoverySalt != hdr.RecoverySalt {
		t.Error("recovery salt mismatch")
	}
	if parsed.RecoveryNonce != hdr.RecoveryNonce {
		t.Error("recovery nonce mismatch")
	}
	if !bytes.Equal(parsed.WrappedMasterKeyRecovery, hdr.WrappedMasterKeyRecovery) {
		t.Error("wrapped recovery key mismatch")
	}
	if parsed.DiskSizeBytes != hdr.DiskSizeBytes {
		t.Error("disk size mismatch")
	}
	if parsed.ExtentSize != hdr.ExtentSize {
		t.Error("extent size mismatch")
	}
	if parsed.Flags != hdr.Flags {
		t.Error("flags mismatch")
	}
}

func TestParseHeader_InvalidMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	copy(buf, "BADMAGIC")
	_, err := ParseHeader(bytes.NewReader(buf))
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
	if !strings.Contains(err.Error(), "invalid container magic") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseHeader_TooShort(t *testing.T) {
	buf := make([]byte, 100) // Way too short
	_, err := ParseHeader(bytes.NewReader(buf))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnlockWithPassword_Correct(t *testing.T) {
	hdr, _, masterKey, err := NewHeader("mypassword", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := UnlockWithPassword(hdr, "mypassword")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ub.MasterKey, masterKey) {
		t.Error("unlocked master key doesn't match original")
	}
}

func TestUnlockWithPassword_Wrong(t *testing.T) {
	hdr, _, _, err := NewHeader("mypassword", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	_, err = UnlockWithPassword(hdr, "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestUnlockWithRecovery_Correct(t *testing.T) {
	hdr, recoveryKey, masterKey, err := NewHeader("mypassword", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := UnlockWithRecovery(hdr, recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ub.MasterKey, masterKey) {
		t.Error("recovery-unlocked master key doesn't match original")
	}
}

func TestUnlockWithRecovery_Wrong(t *testing.T) {
	hdr, _, _, err := NewHeader("mypassword", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	_, err = UnlockWithRecovery(hdr, "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
	if err == nil {
		t.Fatal("expected error for wrong recovery key")
	}
}

func TestRewrapPassword(t *testing.T) {
	hdr, _, masterKey, err := NewHeader("oldpassword", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewrapPassword(hdr, masterKey, "newpassword"); err != nil {
		t.Fatal(err)
	}
	// Old password should fail
	_, err = UnlockWithPassword(hdr, "oldpassword")
	if err == nil {
		t.Fatal("old password should not work after rewrap")
	}
	// New password should work
	ub, err := UnlockWithPassword(hdr, "newpassword")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ub.MasterKey, masterKey) {
		t.Error("master key mismatch after rewrap")
	}
}

func TestRewrapPassword_EmptyPassword(t *testing.T) {
	hdr, _, masterKey, err := NewHeader("password", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	err = RewrapPassword(hdr, masterKey, "")
	if err == nil {
		t.Fatal("expected error for empty new password")
	}
}

func TestRewrapPassword_PreservesRecovery(t *testing.T) {
	hdr, recoveryKey, masterKey, err := NewHeader("oldpassword", 1<<30, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewrapPassword(hdr, masterKey, "newpassword"); err != nil {
		t.Fatal(err)
	}
	// Recovery key should still work after password rewrap
	ub, err := UnlockWithRecovery(hdr, recoveryKey)
	if err != nil {
		t.Fatal("recovery key should still work after password rewrap")
	}
	if !bytes.Equal(ub.MasterKey, masterKey) {
		t.Error("master key via recovery doesn't match after rewrap")
	}
}

func TestWrapHeader_BadMasterKeySize(t *testing.T) {
	_, err := WrapHeader("pass", "RECO-VERY", []byte("short"), 1<<30, 4096)
	if err == nil {
		t.Fatal("expected error for wrong master key size")
	}
}

func TestBuildExtentNonce(t *testing.T) {
	key := make([]byte, MasterKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	n0 := BuildExtentNonce(0, key)
	n1 := BuildExtentNonce(1, key)
	n2 := BuildExtentNonce(0, key)

	// Same inputs produce same nonce
	if n0 != n2 {
		t.Error("same extent index should produce same nonce")
	}
	// Different extent index produces different nonce
	if n0 == n1 {
		t.Error("different extent indices should produce different nonces")
	}
	// First 16 bytes come from the key
	for i := 0; i < 16; i++ {
		if n0[i] != key[i] {
			t.Errorf("nonce[%d] = %d, want %d (from key)", i, n0[i], key[i])
		}
	}
}

func TestSerializeHeader_BadSize(t *testing.T) {
	hdr := &Header{HeaderSize: 999}
	var buf bytes.Buffer
	err := SerializeHeader(&buf, hdr)
	if err == nil {
		t.Fatal("expected error for bad header size")
	}
}

func TestDefaultKDF(t *testing.T) {
	kdf := DefaultKDF()
	if kdf.Time != 3 {
		t.Errorf("time = %d, want 3", kdf.Time)
	}
	if kdf.Memory != 256*1024 {
		t.Errorf("memory = %d, want %d", kdf.Memory, 256*1024)
	}
	if kdf.Threads != 4 {
		t.Errorf("threads = %d, want 4", kdf.Threads)
	}
	if kdf.KeyLen != 32 {
		t.Errorf("key len = %d, want 32", kdf.KeyLen)
	}
}

func TestSerializeParseRoundTrip_MultipleHeaders(t *testing.T) {
	// Verify different passwords/sizes produce distinct serializations
	hdr1, _, _, _ := NewHeader("alpha", 1<<30, 4096)
	hdr2, _, _, _ := NewHeader("beta", 2<<30, 8192)

	var buf1, buf2 bytes.Buffer
	SerializeHeader(&buf1, hdr1)
	SerializeHeader(&buf2, hdr2)

	if bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("different headers should not produce identical serialization")
	}
}

func TestRecoverySalt(t *testing.T) {
	salt := make([]byte, SaltSize)
	rand.Read(salt)
	rs := recoverySalt(salt)
	if len(rs) != SaltSize+4 {
		t.Errorf("recovery salt len = %d, want %d", len(rs), SaltSize+4)
	}
	if !bytes.Equal(rs[:SaltSize], salt) {
		t.Error("recovery salt should start with original salt")
	}
	if string(rs[SaltSize:]) != "reco" {
		t.Error("recovery salt should end with 'reco'")
	}
}
