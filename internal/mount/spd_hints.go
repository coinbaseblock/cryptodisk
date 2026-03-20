package mount

import "strings"

func buildWinSpdUnavailableHint(version, diskSpdPath string) string {
	hint := "ensure the WinSpd/WinFsp.Launcher service is running (try: sc start WinFsp.Launcher), " +
		"or run 'ecdisk repair-backend' as Administrator; " +
		"see https://github.com/winfsp/winfsp/releases for WinFsp updates"
	if strings.Contains(version, "1.0") || strings.Contains(version, "0x0001") {
		hint = "standalone WinSpd 1.0 detected — the IOCTL driver device may not be " +
			"responding; try rebooting or reinstalling with 'ecdisk repair-backend'; " + hint
	}
	if diskSpdPath != "" {
		hint += "; note: Microsoft.DiskSpd installs the DiskSpd benchmark tool, not the WinSpd backend required by ecdisk"
	}
	return hint
}
