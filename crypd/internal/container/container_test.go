package container

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"crypd/internal/cryptovault"
)

func tempDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func TestCreate_Basic(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	recoveryKey, err := Create(path, "testpassword", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if recoveryKey == "" {
		t.Error("recovery key is empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// File should be header + payload
	expectedExtents := (1 << 20) / 4096
	expectedSize := int64(cryptovault.HeaderSize) + int64(expectedExtents)*int64(4096+16)
	if info.Size() != expectedSize {
		t.Errorf("file size = %d, want %d", info.Size(), expectedSize)
	}

	// Permissions should be 0600 (skip on Windows where NTFS has no Unix perms)
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %o, want %o", info.Mode().Perm(), 0o600)
		}
	}
}

func TestCreate_FileExists(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	os.WriteFile(path, []byte("existing"), 0o600)

	_, err := Create(path, "testpassword", 1<<20, 4096)
	if err == nil {
		t.Fatal("expected error when file exists")
	}
}

func TestOpenWithPassword_Success(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "mypassword", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	h, err := OpenWithPassword(path, "mypassword")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.File == nil {
		t.Error("file handle is nil")
	}
	if h.Header == nil {
		t.Error("header is nil")
	}
	if len(h.MasterKey) != cryptovault.MasterKeySize {
		t.Errorf("master key len = %d, want %d", len(h.MasterKey), cryptovault.MasterKeySize)
	}
}

func TestOpenWithPassword_WrongPassword(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "mypassword", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	_, err = OpenWithPassword(path, "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestOpenWithPassword_FileNotFound(t *testing.T) {
	_, err := OpenWithPassword("/nonexistent/path.ecd", "password")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestOpenWithRecovery_Success(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	recoveryKey, err := Create(path, "mypassword", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	h, err := OpenWithRecovery(path, recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if len(h.MasterKey) != cryptovault.MasterKeySize {
		t.Errorf("master key len = %d, want %d", len(h.MasterKey), cryptovault.MasterKeySize)
	}
}

func TestOpenWithRecovery_WrongKey(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "mypassword", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	_, err = OpenWithRecovery(path, "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
	if err == nil {
		t.Fatal("expected error for wrong recovery key")
	}
}

func TestReadWriteExtent(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "password", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	h, err := OpenWithPassword(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Write data to extent 0
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := h.WriteExtent(0, data); err != nil {
		t.Fatal(err)
	}

	// Read it back
	got, err := h.ReadExtent(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("read data doesn't match written data")
	}
}

func TestReadExtent_Unwritten(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "password", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	h, err := OpenWithPassword(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Reading an unwritten extent should return zeros
	got, err := h.ReadExtent(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4096 {
		t.Errorf("extent len = %d, want 4096", len(got))
	}
	for i, b := range got {
		if b != 0 {
			t.Errorf("byte %d = %d, want 0", i, b)
			break
		}
	}
}

func TestWriteExtent_SizeMismatch(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "password", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	h, err := OpenWithPassword(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	err = h.WriteExtent(0, make([]byte, 100)) // Wrong size
	if err == nil {
		t.Fatal("expected error for wrong extent size")
	}
}

func TestReadWriteExtent_MultipleExtents(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "password", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	h, err := OpenWithPassword(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Write different data to multiple extents
	for ext := uint64(0); ext < 5; ext++ {
		data := make([]byte, 4096)
		for i := range data {
			data[i] = byte(ext)
		}
		if err := h.WriteExtent(ext, data); err != nil {
			t.Fatalf("write extent %d: %v", ext, err)
		}
	}

	// Read them back and verify
	for ext := uint64(0); ext < 5; ext++ {
		got, err := h.ReadExtent(ext)
		if err != nil {
			t.Fatalf("read extent %d: %v", ext, err)
		}
		for i, b := range got {
			if b != byte(ext) {
				t.Errorf("extent %d byte %d = %d, want %d", ext, i, b, byte(ext))
				break
			}
		}
	}
}

func TestChangePassword(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "oldpassword", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	// Write some data first
	h, err := OpenWithPassword(path, "oldpassword")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4096)
	for i := range data {
		data[i] = 0xAB
	}
	if err := h.WriteExtent(0, data); err != nil {
		t.Fatal(err)
	}

	// Change password
	if err := h.ChangePassword("newpassword"); err != nil {
		t.Fatal(err)
	}
	h.Close()

	// Old password should fail
	_, err = OpenWithPassword(path, "oldpassword")
	if err == nil {
		t.Fatal("old password should not work")
	}

	// New password should work and data should be intact
	h2, err := OpenWithPassword(path, "newpassword")
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()

	got, err := h2.ReadExtent(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("data should survive password change")
	}
}

func TestClose_NilHandle(t *testing.T) {
	var h *Handle
	if err := h.Close(); err != nil {
		t.Errorf("Close on nil handle: %v", err)
	}
}

func TestClose_NilFile(t *testing.T) {
	h := &Handle{}
	if err := h.Close(); err != nil {
		t.Errorf("Close on nil file: %v", err)
	}
}

func TestClose_ZerosMasterKey(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "password", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	h, err := OpenWithPassword(path, "password")
	if err != nil {
		t.Fatal(err)
	}

	mkCopy := append([]byte(nil), h.MasterKey...)
	h.Close()

	// Master key should be zeroed
	allZero := true
	for _, b := range h.MasterKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("master key should be zeroed after close")
	}

	// The copy should not be zeroed (it's independent)
	anyNonZero := false
	for _, b := range mkCopy {
		if b != 0 {
			anyNonZero = true
			break
		}
	}
	if !anyNonZero {
		t.Error("master key copy should still have data")
	}
}

func TestPayloadLength(t *testing.T) {
	tests := []struct {
		diskSize   uint64
		extentSize uint32
		want       uint64
	}{
		{1024, 512, 2 * (512 + 16)},           // Exact division
		{1025, 512, 3 * (512 + 16)},           // Remainder rounds up
		{4096, 4096, 1 * (4096 + 16)},         // Single extent
		{1 << 20, 4096, 256 * (4096 + 16)},    // 1MB / 4KB = 256 extents
	}
	for _, tc := range tests {
		got := payloadLength(tc.diskSize, tc.extentSize)
		if got != tc.want {
			t.Errorf("payloadLength(%d, %d) = %d, want %d", tc.diskSize, tc.extentSize, got, tc.want)
		}
	}
}

func TestDataPersistsAcrossOpenClose(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "test.ecd")

	_, err := Create(path, "password", 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}

	// Write data and close
	h, err := OpenWithPassword(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	h.WriteExtent(2, data)
	h.Close()

	// Reopen and verify
	h2, err := OpenWithPassword(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()

	got, err := h2.ReadExtent(2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("data should persist across open/close")
	}
}
