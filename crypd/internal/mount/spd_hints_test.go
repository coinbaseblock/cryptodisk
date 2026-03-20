package mount

import (
	"strings"
	"testing"
)

func TestBuildWinSpdUnavailableHint(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		diskSpd  string
		contains []string
		excludes []string
	}{
		{
			name:    "default hint",
			version: "version unavailable",
			contains: []string{
				"sc start WinFsp.Launcher",
				"repair-backend",
			},
			excludes: []string{
				"DiskSpd benchmark tool",
				"standalone WinSpd 1.0 detected",
			},
		},
		{
			name:    "winspd version warning",
			version: "version 1.0 (0x00010000)",
			contains: []string{
				"standalone WinSpd 1.0 detected",
			},
		},
		{
			name:    "diskspd note",
			version: "version unavailable",
			diskSpd: `C:\Program Files\DiskSpd\diskspd.exe`,
			contains: []string{
				"Microsoft.DiskSpd installs the DiskSpd benchmark tool",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildWinSpdUnavailableHint(tt.version, tt.diskSpd)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Fatalf("hint %q missing substring %q", got, want)
				}
			}
			for _, unwanted := range tt.excludes {
				if strings.Contains(got, unwanted) {
					t.Fatalf("hint %q unexpectedly contains %q", got, unwanted)
				}
			}
		})
	}
}

func TestBuildMissingWinSpdDriverHint(t *testing.T) {
	got := buildMissingWinSpdDriverHint()

	for _, want := range []string{
		"WinSpd driver service not installed",
		"repair-backend",
		"future WinFsp release adds integrated SPD support",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("hint %q missing substring %q", got, want)
		}
	}

	if strings.Contains(got, "upgrade to a WinFsp version with integrated SPD support") {
		t.Fatalf("hint %q still implies integrated WinFsp SPD support already exists", got)
	}
}
