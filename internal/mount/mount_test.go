package mount

import (
	"testing"
)

func TestErrBackendMissing(t *testing.T) {
	if ErrBackendMissing == nil {
		t.Fatal("ErrBackendMissing is nil")
	}
	if ErrBackendMissing.Error() != "no block-device backend installed" {
		t.Errorf("unexpected error message: %s", ErrBackendMissing.Error())
	}
}

func TestDefaultBackend_ReturnsBackend(t *testing.T) {
	b := DefaultBackend()
	if b == nil {
		t.Fatal("DefaultBackend returned nil")
	}
}

func TestCheckAvailable_DefaultBackend(t *testing.T) {
	b := DefaultBackend()
	_ = CheckAvailable(b)
}

func TestDefaultBackend_MountNilStore(t *testing.T) {
	b := DefaultBackend()
	err := b.Mount(Options{
		ContainerPath: "/test/container.ecd",
		MountPoint:    "X:",
		IdleSeconds:   900,
		CacheExtents:  128,
	})
	if err == nil {
		t.Fatal("expected error when store is nil")
	}
}

func TestDefaultBackend_UnmountNotMounted(t *testing.T) {
	b := DefaultBackend()
	err := b.Unmount("X:")
	if err == nil {
		t.Fatal("expected error for unmounting non-existent mount")
	}
}

func TestOptions_Fields(t *testing.T) {
	store := newMemExtentStore(4096)
	opts := Options{
		ContainerPath: "/path/to/container.ecd",
		MountPoint:    "Z:",
		IdleSeconds:   300,
		CacheExtents:  64,
		Store:         store,
		DiskSizeBytes: 1 << 30,
		ExtentSize:    4096,
	}
	if opts.ContainerPath != "/path/to/container.ecd" {
		t.Error("ContainerPath mismatch")
	}
	if opts.MountPoint != "Z:" {
		t.Error("MountPoint mismatch")
	}
	if opts.IdleSeconds != 300 {
		t.Error("IdleSeconds mismatch")
	}
	if opts.CacheExtents != 64 {
		t.Error("CacheExtents mismatch")
	}
	if opts.DiskSizeBytes != 1<<30 {
		t.Error("DiskSizeBytes mismatch")
	}
	if opts.ExtentSize != 4096 {
		t.Error("ExtentSize mismatch")
	}
	if opts.Store == nil {
		t.Error("Store is nil")
	}
}

func TestNormalizeMountPoint(t *testing.T) {
	tests := map[string]string{
		"x":                 "X:",
		"x:":                "X:",
		"x:\\":              "X:",
		" x:/ ":             "X:",
		"Z:\\\\":            "Z:",
		"\\\\server\\share": "\\\\server\\share",
		"":                  "",
	}

	for input, want := range tests {
		if got := NormalizeMountPoint(input); got != want {
			t.Fatalf("NormalizeMountPoint(%q) = %q, want %q", input, got, want)
		}
	}
}
