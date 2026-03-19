package app

import (
	"testing"
)

func TestUsage_DoesNotPanic(t *testing.T) {
	// usage() writes to stdout; just verify it doesn't panic.
	usage()
}

func TestPromptInput_Label(t *testing.T) {
	// Verify the UI helper constants are defined and non-empty.
	if colorReset == "" {
		t.Error("colorReset is empty")
	}
	if colorBold == "" {
		t.Error("colorBold is empty")
	}
}

func TestMainMenu_Entries(t *testing.T) {
	if len(mainMenu) == 0 {
		t.Fatal("mainMenu has no groups")
	}
	// Verify each group has entries with non-empty keys and labels.
	seen := map[string]bool{}
	for gi, group := range mainMenu {
		if len(group) == 0 {
			t.Errorf("mainMenu group %d is empty", gi)
		}
		for _, entry := range group {
			if entry.key == "" {
				t.Error("menu entry has empty key")
			}
			if entry.label == "" {
				t.Errorf("menu entry %s has empty label", entry.key)
			}
			if seen[entry.key] {
				t.Errorf("duplicate menu key %s", entry.key)
			}
			seen[entry.key] = true
		}
	}
}

func TestMenuEntry_AllKeysPresent(t *testing.T) {
	// Verify expected menu keys 1-8 are all present.
	expected := []string{"1", "2", "3", "4", "5", "6", "7", "8"}
	keys := map[string]bool{}
	for _, group := range mainMenu {
		for _, e := range group {
			keys[e.key] = true
		}
	}
	for _, k := range expected {
		if !keys[k] {
			t.Errorf("missing menu key %s", k)
		}
	}
}

func TestCmdInit_MissingArgs(t *testing.T) {
	err := cmdInit([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdInspect_MissingArgs(t *testing.T) {
	err := cmdInspect([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdPasswd_MissingArgs(t *testing.T) {
	err := cmdPasswd([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdRecover_MissingArgs(t *testing.T) {
	err := cmdRecover([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdMkVHDX_MissingArgs(t *testing.T) {
	err := cmdMkVHDX([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdDiffVHDX_MissingArgs(t *testing.T) {
	err := cmdDiffVHDX([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdMount_MissingArgs(t *testing.T) {
	err := cmdMount([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdUnmount_MissingArgs(t *testing.T) {
	err := cmdUnmount([]string{})
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestCmdInspect_BadFile(t *testing.T) {
	err := cmdInspect([]string{"--container", "/nonexistent/file.ecd"})
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
