//go:build windows

package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ecdisk/internal/mount"
)

type backendProbe struct {
	Name   string
	OK     bool
	Detail string
	Fix    string
}

type backendArtifacts struct {
	Root        string
	DevSetupExe string
	InfFile     string
	HardwareID  string
	DLLs        []string
}

func backendDoctorMenuSuffix() string {
	return " " + colorDim + "(WinFsp/WinSpd diagnostics)" + colorReset
}

func backendRepairMenuSuffix() string {
	return " " + colorDim + "(WinFsp/WinSpd reset)" + colorReset
}

func cmdBackendDoctor(args []string) error {
	fs := flag.NewFlagSet("backend-doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	report := collectBackendProbes()
	fmt.Println("Windows mount backend diagnostic report")
	fmt.Println(strings.Repeat("=", 39))
	fmt.Println()

	issues := 0
	for _, probe := range report {
		status := "OK"
		prefix := "[OK]"
		if !probe.OK {
			status = "ISSUE"
			prefix = "[!!]"
			issues++
		}
		fmt.Printf("%s %s: %s\n", prefix, probe.Name, status)
		if probe.Detail != "" {
			fmt.Printf("     %s\n", probe.Detail)
		}
		if probe.Fix != "" {
			fmt.Printf("     fix: %s\n", probe.Fix)
		}
		fmt.Println()
	}

	if issues == 0 {
		fmt.Println("Backend status: ready for a mount attempt.")
		return nil
	}

	return fmt.Errorf("backend diagnostic found %d issue(s)", issues)
}

func cmdRepairBackend(args []string) error {
	fs := flag.NewFlagSet("repair-backend", flag.ContinueOnError)
	winfspInstaller := fs.String("winfsp-installer", "", "path to a WinFsp MSI installer or a directory containing one")
	winspdDir := fs.String("winspd-dir", "", "path to an extracted WinSpd payload directory or WinSpd MSI")
	scriptOut := fs.String("script-out", "", "optional path to save a PowerShell repair script")
	dryRun := fs.Bool("dry-run", false, "print checks only; do not modify the system")
	if err := fs.Parse(args); err != nil {
		return err
	}

	artifacts, cleanupArtifacts, artErr := discoverWinSpdArtifacts(*winspdDir)
	defer cleanupArtifacts()
	renderArtifacts := artifacts
	renderArtErr := artErr
	if sourceLooksLikeMSI(*winspdDir) && renderArtErr == nil {
		renderArtifacts = backendArtifacts{}
		renderArtErr = errors.New("WinSpd MSI input is supported for live repair, but --script-out needs an extracted WinSpd payload directory")
	}
	if *scriptOut != "" {
		script, err := renderBackendRepairScript(*winfspInstaller, renderArtifacts, renderArtErr)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*scriptOut, []byte(script), 0o644); err != nil {
			return fmt.Errorf("write script: %w", err)
		}
		fmt.Println("repair script written:", *scriptOut)
	}

	fmt.Println("Starting Windows mount backend repair")
	fmt.Println(strings.Repeat("=", 36))
	fmt.Println()

	if *dryRun {
		fmt.Println("dry-run enabled; no system changes will be made")
		fmt.Println()
		return cmdBackendDoctor(nil)
	}

	if err := step("Pre-flight diagnostic", func() error {
		return printBackendDoctorResult(false)
	}); err != nil {
		fmt.Println("continuing despite diagnostic issues so cleanup can still run")
		fmt.Println()
	}

	if err := step("Stop backend services", stopKnownBackendServices); err != nil {
		fmt.Println("continuing; some services may simply be absent")
		fmt.Println()
	}

	if err := step("Uninstall WinFsp (if present)", uninstallWinFspIfPresent); err != nil {
		fmt.Println("continuing; manual cleanup may still be needed")
		fmt.Println()
	}

	if err := step("Remove stale service registrations", deleteBackendServices); err != nil {
		fmt.Println("continuing; missing services are acceptable")
		fmt.Println()
	}

	if *winfspInstaller != "" {
		if err := step("Install WinFsp", func() error {
			return installWinFsp(*winfspInstaller)
		}); err != nil {
			return err
		}
	} else {
		fmt.Println("[SKIP] Install WinFsp")
		fmt.Println("       --winfsp-installer was not provided")
		fmt.Println()
	}

	if *winspdDir != "" {
		if artErr != nil {
			return fmt.Errorf("winspd payload not usable: %w", artErr)
		}
		if err := step("Deploy WinSpd files", func() error {
			return deployWinSpdArtifacts(artifacts)
		}); err != nil {
			return err
		}
		if err := step("Reinstall WinSpd driver", func() error {
			return reinstallWinSpdDriver(artifacts)
		}); err != nil {
			return err
		}
	} else {
		fmt.Println("[SKIP] Reinstall WinSpd driver")
		fmt.Println("       --winspd-dir was not provided")
		fmt.Println()
	}

	if err := step("Start backend services", startKnownBackendServices); err != nil {
		fmt.Println("continuing; services will start on next reboot or mount attempt")
		fmt.Println()
	}

	if err := step("Final diagnostic", func() error {
		return printBackendDoctorResult(true)
	}); err != nil {
		return err
	}
	return nil
}

func step(name string, fn func() error) error {
	fmt.Printf("[RUN] %s\n", name)
	err := fn()
	if err != nil {
		fmt.Printf("[FAIL] %s\n", name)
		scanAndPrintHints(err)
		fmt.Println()
		return err
	}
	fmt.Printf("[ OK ] %s\n\n", name)
	return nil
}

func printBackendDoctorResult(strict bool) error {
	report := collectBackendProbes()
	issues := 0
	for _, probe := range report {
		mark := "OK"
		if !probe.OK {
			mark = "ISSUE"
			issues++
		}
		fmt.Printf("       %-10s %s\n", mark, probe.Name)
		if probe.Detail != "" {
			fmt.Printf("                  %s\n", probe.Detail)
		}
		if !probe.OK && probe.Fix != "" {
			fmt.Printf("                  fix: %s\n", probe.Fix)
		}
	}
	if strict && issues > 0 {
		return fmt.Errorf("backend still reports %d issue(s)", issues)
	}
	if issues > 0 {
		return fmt.Errorf("backend currently reports %d issue(s)", issues)
	}
	return nil
}

func collectBackendProbes() []backendProbe {
	probes := []backendProbe{}

	probes = append(probes, backendProbe{
		Name:   "Current user",
		OK:     isRunningAsAdmin(),
		Detail: adminDetail(),
		Fix:    "run Command Prompt as Administrator before repairing drivers or services",
	})

	installDir := detectWinFspInstallDir()
	probes = append(probes, backendProbe{
		Name:   "WinFsp install",
		OK:     installDir != "",
		Detail: valueOrFallback(installDir, "WinFsp registry key not found"),
		Fix:    "install WinFsp first, then rerun repair-backend with --winfsp-installer <path-to-msi>",
	})

	dlls := discoverDLLCandidates()
	probes = append(probes, backendProbe{
		Name:   "SPD DLL",
		OK:     len(dlls) > 0,
		Detail: valueOrFallback(strings.Join(dlls, ", "), "no winspd/winfsp SPD-capable DLL found near ecdisk.exe, current directory, or WinFsp bin"),
		Fix:    "place a compatible winspd-*.dll next to ecdisk.exe or provide --winspd-dir to repair-backend",
	})

	services := detectServiceStates([]string{"WinSpd", "WinSpd.Launcher", "WinFsp.Launcher"})
	probes = append(probes, backendProbe{
		Name:   "Driver services",
		OK:     hasHealthyBackendService(services),
		Detail: renderServiceStates(services),
		Fix:    "start a backend service (sc start WinFsp.Launcher) or rerun repair-backend to reinstall; at least one service must be running",
	})

	openErr := diagnoseMountOpen()
	probes = append(probes, backendProbe{
		Name:   "Mount preflight",
		OK:     openErr == nil,
		Detail: valueOrFallback(errorString(openErr), "backend DLL/driver handshake succeeded"),
		Fix:    "if the DLL exists but the handshake fails, remove stale services/files and redeploy matching DLL + driver bits from the same WinSpd package",
	})

	diskSpdPath := detectDiskSpdInstall()
	probes = append(probes, backendProbe{
		Name:   "DiskSpd package confusion",
		OK:     !(openErr != nil && diskSpdPath != ""),
		Detail: valueOrFallback(diskSpdPath, "diskspd.exe not found on PATH"),
		Fix:    "Microsoft.DiskSpd is the DiskSpd benchmark tool, not the WinSpd backend; do not use winget install Microsoft.DiskSpd as a substitute for WinSpd",
	})

	return probes
}

func detectDiskSpdInstall() string {
	path, err := exec.LookPath("diskspd.exe")
	if err != nil {
		return ""
	}
	return path
}

func detectServiceStates(names []string) map[string]string {
	states := make(map[string]string, len(names))
	for _, name := range names {
		out, err := exec.Command("sc", "query", name).CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil {
			states[name] = "missing"
			continue
		}
		state := "installed"
		re := regexp.MustCompile(`STATE\s*:\s*\d+\s+([A-Z_]+)`)
		if m := re.FindStringSubmatch(text); len(m) == 2 {
			state = strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))
		}
		states[name] = state
	}
	return states
}

func renderServiceStates(states map[string]string) string {
	keys := make([]string, 0, len(states))
	for k := range states {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, states[k]))
	}
	return strings.Join(parts, ", ")
}

func hasHealthyBackendService(states map[string]string) bool {
	for _, state := range states {
		if state == "running" || state == "start-pending" {
			return true
		}
	}
	return false
}

func detectWinFspInstallDir() string {
	for _, key := range []string{
		`HKLM\SOFTWARE\WOW6432Node\WinFsp`,
		`HKLM\SOFTWARE\WinFsp`,
		`HKCU\SOFTWARE\WinFsp`,
	} {
		out, err := exec.Command("reg", "query", key, "/v", "InstallDir").CombinedOutput()
		if err != nil {
			continue
		}
		if dir := parseRegValue(string(out), "InstallDir"); dir != "" {
			return dir
		}
	}
	return ""
}

func discoverDLLCandidates() []string {
	seen := map[string]bool{}
	var dlls []string
	for _, dir := range probeDirs() {
		matches, _ := filepath.Glob(filepath.Join(dir, "win*sp*-*.dll"))
		for _, match := range matches {
			base := strings.ToLower(filepath.Base(match))
			if !(strings.HasPrefix(base, "winspd-") || strings.HasPrefix(base, "winfsp-")) {
				continue
			}
			if !seen[match] {
				seen[match] = true
				dlls = append(dlls, match)
			}
		}
	}
	sort.Strings(dlls)
	return dlls
}

func probeDirs() []string {
	seen := map[string]bool{}
	var dirs []string
	if exePath, err := os.Executable(); err == nil {
		dir := filepath.Dir(exePath)
		if dir != "" && !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if wd != "" && !seen[wd] {
			seen[wd] = true
			dirs = append(dirs, wd)
		}
	}
	if installDir := detectWinFspInstallDir(); installDir != "" {
		binDir := filepath.Join(installDir, "bin")
		if !seen[binDir] {
			seen[binDir] = true
			dirs = append(dirs, binDir)
		}
	}
	return dirs
}

func parseRegValue(output, valueName string) string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(strings.ToLower(line), strings.ToLower(valueName)+" ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		return strings.Join(fields[2:], " ")
	}
	return ""
}

func diagnoseMountOpen() error {
	return mount.CheckAvailable(mount.DefaultBackend())
}

func isRunningAsAdmin() bool {
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

func adminDetail() string {
	if isRunningAsAdmin() {
		return "administrator privileges detected"
	}
	return "administrator privileges not detected"
}

func valueOrFallback(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func stopKnownBackendServices() error {
	var firstErr error
	for _, name := range []string{"WinSpd", "WinSpd.Launcher", "WinFsp.Launcher"} {
		out, err := exec.Command("sc", "stop", name).CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil && !strings.Contains(strings.ToLower(text), "service has not been started") && !strings.Contains(strings.ToLower(text), "does not exist") {
			if firstErr == nil {
				firstErr = fmt.Errorf("stop %s: %v\n%s", name, err, text)
			}
		}
		if text != "" {
			fmt.Println(indent(text, "       "))
		}
	}
	return firstErr
}

func startKnownBackendServices() error {
	var firstErr error
	for _, name := range []string{"WinFsp.Launcher", "WinSpd", "WinSpd.Launcher"} {
		out, err := exec.Command("sc", "query", name).CombinedOutput()
		text := string(out)
		if err != nil {
			continue // service not installed
		}
		if strings.Contains(text, "RUNNING") {
			fmt.Printf("       %s already running\n", name)
			continue
		}
		startOut, startErr := exec.Command("sc", "start", name).CombinedOutput()
		startText := strings.TrimSpace(string(startOut))
		if startErr != nil {
			if !strings.Contains(strings.ToLower(startText), "already been started") {
				if firstErr == nil {
					firstErr = fmt.Errorf("start %s: %v\n%s", name, startErr, startText)
				}
			}
		}
		if startText != "" {
			fmt.Println(indent(startText, "       "))
		}
	}
	return firstErr
}

func uninstallWinFspIfPresent() error {
	uninstallCmd, displayName := findWinFspUninstallCommand()
	if uninstallCmd == "" {
		fmt.Println("       WinFsp uninstall entry not found; nothing to remove")
		return nil
	}
	fmt.Printf("       found %s\n", displayName)
	cmdLine := uninstallCmd
	lower := strings.ToLower(cmdLine)
	if strings.Contains(lower, "msiexec") {
		if strings.Contains(lower, "/i") && !strings.Contains(lower, "/x") {
			cmdLine = replaceMSIAction(cmdLine)
		}
		if !strings.Contains(lower, "/qn") {
			cmdLine += " /qn"
		}
		if !strings.Contains(lower, "/norestart") {
			cmdLine += " /norestart"
		}
	}
	return runCmd("cmd", "/C", cmdLine)
}

func findWinFspUninstallCommand() (string, string) {
	roots := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	for _, root := range roots {
		out, err := exec.Command("reg", "query", root, "/s", "/f", "WinFsp").CombinedOutput()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		currentKey := ""
		displayName := ""
		uninstall := ""
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "HKEY_") {
				currentKey = line
				displayName = ""
				uninstall = ""
				continue
			}
			if v := parseRegValue(line, "DisplayName"); v != "" {
				displayName = v
			}
			if v := parseRegValue(line, "UninstallString"); v != "" {
				uninstall = v
			}
			if currentKey != "" && strings.Contains(strings.ToLower(displayName), "winfsp") && uninstall != "" {
				return uninstall, displayName
			}
		}
	}
	return "", ""
}

func replaceMSIAction(cmdLine string) string {
	re := regexp.MustCompile(`(?i)/i\s+`)
	if re.MatchString(cmdLine) {
		return re.ReplaceAllString(cmdLine, "/x ")
	}
	return cmdLine
}

func deleteBackendServices() error {
	var firstErr error
	for _, name := range []string{"WinSpd", "WinSpd.Launcher"} {
		out, err := exec.Command("sc", "delete", name).CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil && !strings.Contains(strings.ToLower(text), "does not exist") {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete %s: %v\n%s", name, err, text)
			}
		}
		if text != "" {
			fmt.Println(indent(text, "       "))
		}
	}
	return firstErr
}

func installWinFsp(installer string) error {
	resolved, err := resolveWinFspInstaller(installer)
	if err != nil {
		return err
	}
	return runCmd("msiexec.exe", "/i", resolved, "/qn", "/norestart")
}

func resolveWinFspInstaller(installer string) (string, error) {
	installer = strings.TrimSpace(installer)
	if installer == "" {
		return "", errors.New("WinFsp installer path is empty")
	}

	info, err := os.Stat(installer)
	if err != nil {
		return "", fmt.Errorf("WinFsp installer not found: %w", err)
	}

	if !info.IsDir() {
		if strings.EqualFold(filepath.Ext(installer), ".msi") {
			return installer, nil
		}
		return "", fmt.Errorf("WinFsp installer must be an .msi file or a directory containing one: %s", installer)
	}

	matches, err := filepath.Glob(filepath.Join(installer, "winfsp-*.msi"))
	if err != nil {
		return "", fmt.Errorf("search WinFsp installer: %w", err)
	}
	if len(matches) == 0 {
		matches, err = filepath.Glob(filepath.Join(installer, "*.msi"))
		if err != nil {
			return "", fmt.Errorf("search WinFsp installer: %w", err)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no WinFsp MSI found in directory: %s", installer)
	}
	if len(matches) > 1 {
		sort.Strings(matches)
		for _, match := range matches {
			if strings.Contains(strings.ToLower(filepath.Base(match)), "winfsp") {
				return match, nil
			}
		}
		return "", fmt.Errorf("multiple MSI files found in %s; pass the exact WinFsp MSI path", installer)
	}
	return matches[0], nil
}

func sourceLooksLikeMSI(path string) bool {
	resolved, err := resolveOptionalLocalPath(path)
	if err != nil {
		resolved = strings.TrimSpace(path)
	}
	return strings.EqualFold(filepath.Ext(resolved), ".msi")
}

func discoverWinSpdArtifacts(root string) (backendArtifacts, func(), error) {
	if strings.TrimSpace(root) == "" {
		return backendArtifacts{}, func() {}, errors.New("WinSpd payload path was not provided")
	}

	resolved, err := resolveOptionalLocalPath(root)
	if err != nil {
		return backendArtifacts{}, func() {}, err
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return backendArtifacts{}, func() {}, err
	}

	cleanup := func() {}
	if !info.IsDir() {
		if !strings.EqualFold(filepath.Ext(resolved), ".msi") {
			return backendArtifacts{}, cleanup, fmt.Errorf("WinSpd payload must be a directory or .msi file: %s", resolved)
		}
		extractedRoot, extractErr := extractMSIToTemp(resolved)
		if extractErr != nil {
			return backendArtifacts{}, cleanup, fmt.Errorf("extract WinSpd MSI: %w", extractErr)
		}
		resolved = extractedRoot
		cleanup = func() { _ = os.RemoveAll(extractedRoot) }
	}

	art, err := scanWinSpdPayload(resolved)
	if err != nil {
		return art, cleanup, err
	}
	return art, cleanup, nil
}

func resolveOptionalLocalPath(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("path is empty")
	}
	if _, err := os.Stat(input); err == nil {
		return filepath.Clean(input), nil
	}
	base := filepath.Base(input)
	for _, dir := range probeDirs() {
		candidate := filepath.Join(dir, base)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("path not found: %s", input)
}

func extractMSIToTemp(msiPath string) (string, error) {
	tempDir, err := os.MkdirTemp("", "ecdisk-winspd-*")
	if err != nil {
		return "", err
	}
	cmd := exec.Command("msiexec.exe", "/a", msiPath, "/qn", "/norestart", "TARGETDIR="+tempDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return "", fmt.Errorf("%w\n%s", err, msg)
		}
		return "", err
	}
	return tempDir, nil
}

func scanWinSpdPayload(root string) (backendArtifacts, error) {
	root = filepath.Clean(root)
	art := backendArtifacts{Root: root}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		switch {
		case strings.HasPrefix(name, "devsetup-") && strings.HasSuffix(name, ".exe") && art.DevSetupExe == "":
			art.DevSetupExe = path
		case strings.HasSuffix(name, ".inf") && art.InfFile == "":
			art.InfFile = path
		case strings.HasPrefix(name, "winspd-") && strings.HasSuffix(name, ".dll"):
			art.DLLs = append(art.DLLs, path)
		}
		return nil
	})
	if err != nil {
		return backendArtifacts{}, err
	}
	if art.DevSetupExe == "" {
		return art, errors.New("missing devsetup-*.exe in WinSpd payload")
	}
	if art.InfFile == "" {
		return art, errors.New("missing WinSpd .inf file in payload")
	}
	if len(art.DLLs) == 0 {
		return art, errors.New("missing winspd-*.dll in payload")
	}
	art.HardwareID, err = parseHardwareIDFromINF(art.InfFile)
	if err != nil {
		return art, err
	}
	sort.Strings(art.DLLs)
	return art, nil
}

func parseHardwareIDFromINF(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?im)root\\[a-z0-9._-]+`)
	match := re.FindString(string(data))
	if match == "" {
		return "", errors.New("could not find ROOT\\... hardware ID in INF")
	}
	return match, nil
}

func deployWinSpdArtifacts(art backendArtifacts) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	destDir := filepath.Dir(exePath)
	copied := 0
	err = filepath.WalkDir(art.Root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !(strings.HasPrefix(name, "winspd-") || strings.HasPrefix(name, "launch") || strings.HasPrefix(name, "devsetup-")) {
			return nil
		}
		dst := filepath.Join(destDir, d.Name())
		if err := copyFile(path, dst); err != nil {
			return err
		}
		fmt.Printf("       copied %s -> %s\n", path, dst)
		copied++
		return nil
	})
	if err != nil {
		return err
	}
	if copied == 0 {
		return errors.New("no WinSpd payload files were copied")
	}
	return nil
}

func reinstallWinSpdDriver(art backendArtifacts) error {
	fmt.Printf("       hardware id: %s\n", art.HardwareID)
	if err := runCmd(art.DevSetupExe, "remove", art.HardwareID); err != nil {
		fmt.Println("       remove returned error; continuing with add in case driver was already absent")
	}
	const maxAttempts = 6
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := runCmd(art.DevSetupExe, "add", art.HardwareID, art.InfFile)
		if err == nil {
			return nil
		}
		if !isRetryableDriverReinstallError(err) || attempt == maxAttempts {
			return err
		}
		wait := time.Duration(attempt) * time.Second
		fmt.Printf("       driver install is waiting for the previous device/service deletion to finish; retrying in %s\n", wait)
		time.Sleep(wait)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		// On Windows a loaded DLL can be renamed even though it cannot be
		// overwritten.  Move the locked file aside and try again.
		old := dst + ".old"
		os.Remove(old) // best-effort cleanup of a previous .old
		if renameErr := os.Rename(dst, old); renameErr != nil {
			return fmt.Errorf("%w (also failed to rename locked file: %v)", err, renameErr)
		}
		out, err = os.Create(dst)
		if err != nil {
			os.Rename(old, dst) // try to restore
			return err
		}
	}
	defer out.Close()
	if _, err := out.ReadFrom(in); err != nil {
		return err
	}
	return out.Close()
}

func runCmd(name string, args ...string) error {
	fmt.Printf("       > %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if text := strings.TrimSpace(string(out)); text != "" {
		fmt.Println(indent(text, "       "))
	}
	if err != nil {
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

func isRetryableDriverReinstallError(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1072 {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "exit status 1072") ||
		strings.Contains(msg, "marked for deletion")
}

func scanAndPrintHints(err error) {
	msg := strings.ToLower(err.Error())
	fmt.Printf("       error: %v\n", err)
	switch {
	case strings.Contains(msg, "access is denied"):
		fmt.Println("       hint: rerun the command in an elevated Administrator console")
	case strings.Contains(msg, "cannot find the file"), strings.Contains(msg, "not found"):
		fmt.Println("       hint: verify the installer/payload path and make sure the required files exist")
	case strings.Contains(msg, "still reports"):
		fmt.Println("       hint: rerun `ecdisk.exe backend-doctor` to see the remaining failing probe")
	}
}

func renderBackendRepairScript(winfspInstaller string, art backendArtifacts, artErr error) (string, error) {
	exeName := "ecdisk.exe"
	if exePath, err := os.Executable(); err == nil {
		exeName = filepath.Base(exePath)
	}
	winfspInstaller = escapePS(winfspInstaller)
	winspdDir := ""
	devSetup := ""
	infFile := ""
	hardwareID := ""
	if artErr == nil {
		winspdDir = escapePS(art.Root)
		devSetup = escapePS(art.DevSetupExe)
		infFile = escapePS(art.InfFile)
		hardwareID = escapePS(art.HardwareID)
	}
	warning := ""
	if artErr != nil {
		warning = escapePS(artErr.Error())
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
Write-Host 'ECDISK backend repair helper'
Write-Host '==========================='

function Run-Step($name, [scriptblock]$body) {
  Write-Host "[RUN] $name"
  try {
    & $body
    Write-Host "[ OK ] $name" -ForegroundColor Green
  } catch {
    Write-Host "[FAIL] $name" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    throw
  }
  Write-Host ''
}

Run-Step 'Stop backend services' {
  foreach ($svc in 'WinSpd', 'WinSpd.Launcher', 'WinFsp.Launcher') {
    sc.exe stop $svc | Out-Host
  }
}

Run-Step 'Delete stale backend services' {
  foreach ($svc in 'WinSpd', 'WinSpd.Launcher') {
    sc.exe delete $svc | Out-Host
  }
}

Run-Step 'Install WinFsp (optional)' {
  $installer = '%s'
  if ([string]::IsNullOrWhiteSpace($installer)) {
    Write-Host 'Skipping WinFsp reinstall because no installer path was provided.' -ForegroundColor Yellow
    return
  }
  if (-not (Test-Path $installer)) {
    throw "WinFsp installer not found: $installer"
  }
  Start-Process msiexec.exe -ArgumentList @('/i', $installer, '/qn', '/norestart') -Wait -NoNewWindow
}

Run-Step 'Reinstall WinSpd driver (optional)' {
  $payloadDir = '%s'
  $devsetup = '%s'
  $inf = '%s'
  $hwid = '%s'
  if ([string]::IsNullOrWhiteSpace($payloadDir)) {
    Write-Host 'Skipping WinSpd reinstall because no usable payload was supplied.' -ForegroundColor Yellow
    if ('%s' -ne '') {
      Write-Host 'Reason: %s' -ForegroundColor Yellow
    }
    return
  }
  if (-not (Test-Path $devsetup)) { throw "devsetup not found: $devsetup" }
  if (-not (Test-Path $inf)) { throw "INF not found: $inf" }
  & $devsetup remove $hwid | Out-Host
  & $devsetup add $hwid $inf | Out-Host
}

Run-Step 'Final diagnostic' {
  if (Test-Path '.\\%s') {
    & '.\\%s' backend-doctor
  } else {
    Write-Host 'Run ecdisk.exe backend-doctor manually to verify the final state.' -ForegroundColor Yellow
  }
}
`, winfspInstaller, winspdDir, devSetup, infFile, hardwareID, warning, warning, exeName, exeName), nil
}

func escapePS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
