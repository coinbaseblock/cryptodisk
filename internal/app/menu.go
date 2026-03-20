package app

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"

	"ecdisk/internal/mount"
)

// ─── UI helpers ──────────────────────────────────────────────────────

const (
	colorReset = "\033[0m"
	colorBold  = "\033[1m"
	colorDim   = "\033[2m"
	colorCyan  = "\033[36m"
	colorGreen = "\033[32m"
	colorRed   = "\033[31m"
)

func menuHeader(title string) {
	fmt.Printf("\n  %s── %s ──%s\n\n", colorCyan+colorBold, title, colorReset)
}

func successMsg(msg string) {
	fmt.Printf("\n  %s✓ %s%s\n\n", colorGreen, msg, colorReset)
}

func errorMsg(msg string) {
	fmt.Printf("\n  %s✗ %s%s\n\n", colorRed, msg, colorReset)
}

func promptInput(label string) (string, error) {
	fmt.Printf("  %s›%s %s", colorCyan, colorReset, label)
	br := bufio.NewReader(os.Stdin)
	s, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// ─── Interactive menu ────────────────────────────────────────────────

type menuEntry struct {
	key, label string
}

var mainMenu = [][]menuEntry{
	{
		{"1", "Create Container"},
		{"2", "Inspect Container"},
		{"3", "Change Password"},
		{"4", "Recover Container"},
	},
	{
		{"5", "Create VHDX"},
		{"6", "Create Diff VHDX"},
	},
	{
		{"7", "Mount Container"},
		{"8", "Unmount Container"},
		{"9", "Repair Mount Backend"},
	},
}

// mountMenuSuffix returns an informational suffix for mount menu items on
// Windows, where mount support depends on an external WinSpd-compatible
// backend. The menu still exposes the actions so users can try mounting and
// receive the concrete backend error from the runtime check.
func mountMenuSuffix() string {
	if runtime.GOOS == "windows" {
		return " " + colorDim + "(requires WinSpd-compatible backend)" + colorReset
	}
	return ""
}

func menuLabel(entry menuEntry) string {
	switch entry.key {
	case "7", "8":
		return entry.label + mountMenuSuffix()
	case "9":
		return entry.label + backendRepairMenuSuffix()
	default:
		return entry.label
	}
}

func interactiveMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n  %sECDISK v1.0%s\n", colorBold, colorReset)

		for _, group := range mainMenu {
			fmt.Println()
			for _, item := range group {
				fmt.Printf("    %s%s%s  %s\n", colorGreen, item.key, colorReset, menuLabel(item))
			}
		}
		fmt.Printf("\n    %s0%s  Exit\n", colorDim, colorReset)

		fmt.Printf("\n  %s>%s ", colorBold, colorReset)

		choice, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		switch strings.TrimSpace(choice) {
		case "1":
			menuCreateContainer()
		case "2":
			menuInspect()
		case "3":
			menuPasswd()
		case "4":
			menuRecover()
		case "5":
			menuMkVHDX()
		case "6":
			menuDiffVHDX()
		case "7":
			menuMount()
		case "8":
			menuUnmount()
		case "9":
			menuBackendRepair()
		case "0", "q", "Q":
			fmt.Println()
			return
		default:
			errorMsg("Invalid option")
		}

		fmt.Printf("  %sPress Enter to continue...%s", colorDim, colorReset)
		reader.ReadString('\n')
		fmt.Print("\033[2J\033[H")
	}
}

// ─── Menu handlers ──────────────────────────────────────────────────

func menuCreateContainer() {
	menuHeader("Create Container")

	path, err := promptInput("Container file path: ")
	if err != nil || path == "" {
		errorMsg("Container path is required")
		return
	}

	sizeStr, err := promptInput("Disk size in GB: ")
	if err != nil || sizeStr == "" {
		errorMsg("Size is required")
		return
	}

	extentStr, _ := promptInput("Extent size in MB (default 4): ")
	if extentStr == "" {
		extentStr = "4"
	}

	args := []string{"--container", path, "--size-gb", sizeStr, "--extent-mb", extentStr}
	if err := cmdInit(args); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("Container created successfully!")
	}
}

func menuInspect() {
	menuHeader("Inspect Container")

	path, err := promptInput("Container file path: ")
	if err != nil || path == "" {
		errorMsg("Container path is required")
		return
	}

	fmt.Println()
	if err := cmdInspect([]string{"--container", path}); err != nil {
		errorMsg(err.Error())
	}
}

func menuPasswd() {
	menuHeader("Change Password")

	path, err := promptInput("Container file path: ")
	if err != nil || path == "" {
		errorMsg("Container path is required")
		return
	}

	if err := cmdPasswd([]string{"--container", path}); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("Password changed successfully!")
	}
}

func menuRecover() {
	menuHeader("Recover Container")

	path, err := promptInput("Container file path: ")
	if err != nil || path == "" {
		errorMsg("Container path is required")
		return
	}

	key, err := promptInput("Recovery key: ")
	if err != nil || key == "" {
		errorMsg("Recovery key is required")
		return
	}

	if err := cmdRecover([]string{"--container", path, "--recovery", key}); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("Container recovered and password reset!")
	}
}

func menuMkVHDX() {
	menuHeader("Create VHDX")

	path, err := promptInput("VHDX file path: ")
	if err != nil || path == "" {
		errorMsg("Path is required")
		return
	}

	sizeStr, err := promptInput("Size in GB: ")
	if err != nil || sizeStr == "" {
		errorMsg("Size is required")
		return
	}

	blockStr, _ := promptInput("Block size in MB (default 4): ")
	if blockStr == "" {
		blockStr = "4"
	}

	if err := cmdMkVHDX([]string{"--path", path, "--size-gb", sizeStr, "--block-mb", blockStr}); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("VHDX created successfully!")
	}
}

func menuDiffVHDX() {
	menuHeader("Create Differencing VHDX")

	base, err := promptInput("Base VHDX path: ")
	if err != nil || base == "" {
		errorMsg("Base path is required")
		return
	}

	path, err := promptInput("New VHDX path: ")
	if err != nil || path == "" {
		errorMsg("Path is required")
		return
	}

	blockStr, _ := promptInput("Block size in MB (default 4): ")
	if blockStr == "" {
		blockStr = "4"
	}

	if err := cmdDiffVHDX([]string{"--path", path, "--base", base, "--block-mb", blockStr}); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("Differencing VHDX created successfully!")
	}
}

func menuMount() {
	menuHeader("Mount Container")

	if runtime.GOOS == "windows" {
		if err := mount.CheckAvailable(mount.DefaultBackend()); err != nil {
			fmt.Printf("  %sNote:%s Windows mount still depends on a WinSpd-compatible\n", colorDim, colorReset)
			fmt.Printf("  backend. This menu will still let you try the mount so you can see\n")
			fmt.Printf("  the exact runtime error if the backend is missing or incompatible.\n")
			fmt.Printf("  Current check: %v\n\n", err)
		}
	}

	path, err := promptInput("Container file path: ")
	if err != nil || path == "" {
		errorMsg("Container path is required")
		return
	}

	mountPoint, err := promptInput("Mount point (e.g. X:): ")
	if err != nil || mountPoint == "" {
		errorMsg("Mount point is required")
		return
	}

	idleStr, _ := promptInput("Idle timeout seconds (default 900): ")
	if idleStr == "" {
		idleStr = "900"
	}

	cacheStr, _ := promptInput("Cache extents (default 128): ")
	if cacheStr == "" {
		cacheStr = "128"
	}

	args := []string{"--container", path, "--mount", mountPoint, "--idle-seconds", idleStr, "--cache-extents", cacheStr}
	if err := cmdMount(args); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("Container mounted!")
	}
}

func menuBackendRepair() {
	menuHeader("Repair Mount Backend")

	if runtime.GOOS != "windows" {
		errorMsg("Backend repair is only available on Windows")
		return
	}

	winfspInstaller, _ := promptInput("WinFsp MSI file or directory (optional): ")
	winspdDir, _ := promptInput("WinSpd payload directory or MSI (optional): ")
	scriptOut, _ := promptInput("Write PowerShell script to file (optional): ")

	args := []string{}
	if strings.TrimSpace(winfspInstaller) != "" {
		args = append(args, "--winfsp-installer", winfspInstaller)
	}
	if strings.TrimSpace(winspdDir) != "" {
		args = append(args, "--winspd-dir", winspdDir)
	}
	if strings.TrimSpace(scriptOut) != "" {
		args = append(args, "--script-out", scriptOut)
	}

	if err := cmdRepairBackend(args); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("Backend repair completed")
	}
}

func menuUnmount() {
	menuHeader("Unmount Container")

	if runtime.GOOS == "windows" {
		if err := mount.CheckAvailable(mount.DefaultBackend()); err != nil {
			fmt.Printf("  %sNote:%s Windows unmount still depends on the same backend used by\n", colorDim, colorReset)
			fmt.Printf("  mount. This menu remains available so you can try it and get the\n")
			fmt.Printf("  exact runtime error instead of being blocked up front.\n")
			fmt.Printf("  Current check: %v\n\n", err)
		}
	}

	mountPoint, err := promptInput("Mount point (e.g. X:): ")
	if err != nil || mountPoint == "" {
		errorMsg("Mount point is required")
		return
	}

	if err := cmdUnmount([]string{"--mount", mountPoint}); err != nil {
		errorMsg(err.Error())
	} else {
		successMsg("Container unmounted!")
	}
}
