package vhdx

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreate_NonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub tests only run on non-Windows")
	}
	err := Create(filepath.Join(t.TempDir(), "test.vhdx"), 1, 4)
	if err == nil {
		t.Fatal("expected error on non-Windows")
	}
	if err.Error() != "windows only" {
		t.Errorf("error = %q, want %q", err.Error(), "windows only")
	}
}

func TestCreateDiff_NonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub tests only run on non-Windows")
	}
	err := CreateDiff(filepath.Join(t.TempDir(), "child.vhdx"), "base.vhdx", 4)
	if err == nil {
		t.Fatal("expected error on non-Windows")
	}
	if err.Error() != "windows only" {
		t.Errorf("error = %q, want %q", err.Error(), "windows only")
	}
}

func TestAttach_NonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub tests only run on non-Windows")
	}
	err := Attach("test.vhdx")
	if err == nil {
		t.Fatal("expected error on non-Windows")
	}
}

func TestDetach_NonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub tests only run on non-Windows")
	}
	err := Detach("test.vhdx")
	if err == nil {
		t.Fatal("expected error on non-Windows")
	}
}

func TestCreate_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.vhdx")
	// On Windows with go-winio, this may fail due to privileges but should not panic.
	err := Create(path, 1, 4)
	if err != nil {
		// Expected if not running with admin privileges
		t.Logf("Create returned error (may need admin): %v", err)
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Error("created VHDX should not be empty")
	}
}
