//go:build windows

package mount

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"ecdisk/internal/autolock"
)

// ── WinSpd DLL bindings ─────────────────────────────────────────

// spdDLLCandidates lists DLL names to try, in order of preference.
// The SPD (Storage Proxy Driver) API lives in the standalone WinSpd DLL
// (winspd-{arch}.dll) from https://github.com/winfsp/winspd. WinFsp does
// NOT export SPD symbols; we include winfsp-{arch}.dll as a speculative
// fallback in case a future WinFsp release integrates SPD support.
// On ARM64 Windows we prefer the a64 (native) DLLs first, then fall back
// to x64 which may work under emulation.
var spdDLLCandidates = func() []string {
	if runtime.GOARCH == "arm64" {
		return []string{
			"winspd-a64.dll",
			"winfsp-a64.dll",
			"winspd-x64.dll",
			"winfsp-x64.dll",
		}
	}
	return []string{
		"winspd-x64.dll",
		"winfsp-x64.dll",
	}
}()

var (
	winSpdDLL *windows.LazyDLL

	procHandleOpen     *windows.LazyProc
	procHandleTransact *windows.LazyProc
	procHandleClose    *windows.LazyProc

	procIoctlOpenDevice  *windows.LazyProc
	procIoctlProvision   *windows.LazyProc
	procIoctlTransact    *windows.LazyProc
	procIoctlUnprovision *windows.LazyProc

	procVersion *windows.LazyProc

	dllInitOnce sync.Once
	dllInitErr  error
)

// winfspInstallDir queries the Windows registry for WinFsp's installation
// directory and returns the path to its DLL folder (bin/). Returns "" if
// WinFsp is not found in the registry.
func winfspInstallDir() string {
	for _, root := range []windows.Handle{windows.HKEY_LOCAL_MACHINE, windows.HKEY_CURRENT_USER} {
		var k windows.Handle
		kpath, _ := windows.UTF16PtrFromString(`SOFTWARE\WinFsp`)
		if err := windows.RegOpenKeyEx(root, kpath, 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &k); err != nil {
			// Also try the 32-bit view (WinFsp may register there).
			if err := windows.RegOpenKeyEx(root, kpath, 0, windows.KEY_READ|windows.KEY_WOW64_32KEY, &k); err != nil {
				continue
			}
		}
		defer windows.RegCloseKey(k)

		vname, _ := windows.UTF16PtrFromString("InstallDir")
		var dtype uint32
		var size uint32
		if err := windows.RegQueryValueEx(k, vname, nil, &dtype, nil, &size); err != nil || size == 0 {
			continue
		}
		buf := make([]uint16, size/2)
		if err := windows.RegQueryValueEx(k, vname, nil, &dtype, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
			continue
		}
		dir := strings.TrimRight(windows.UTF16ToString(buf), "\x00")
		if dir != "" {
			return dir + `bin\`
		}
	}
	return ""
}

func initSpdDLL() error {
	dllInitOnce.Do(func() {
		// Build search list: bare name (system PATH), then exe directory,
		// then WinFsp's registry install directory.
		candidates := make([]string, 0, len(spdDLLCandidates)*3)
		for _, name := range spdDLLCandidates {
			candidates = append(candidates, name)
		}
		// Also search the directory where the executable lives — supports
		// portable/uninstalled deployments with DLLs next to the .exe.
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath) + string(filepath.Separator)
			for _, name := range spdDLLCandidates {
				candidates = append(candidates, exeDir+name)
			}
		}
		if dir := winfspInstallDir(); dir != "" {
			for _, name := range spdDLLCandidates {
				candidates = append(candidates, dir+name)
			}
		}

		for _, name := range candidates {
			dll := windows.NewLazyDLL(name)
			if err := dll.Load(); err != nil {
				continue
			}
			// Check that at least one API set (Handle or IOCTL) is present.
			hOpen := dll.NewProc("SpdStorageUnitHandleOpen")
			iOpen := dll.NewProc("SpdIoctlOpenDevice")
			if hOpen.Find() != nil && iOpen.Find() != nil {
				continue // DLL exists but has no SPD exports
			}
			winSpdDLL = dll
			procHandleOpen = dll.NewProc("SpdStorageUnitHandleOpen")
			procHandleTransact = dll.NewProc("SpdStorageUnitHandleTransact")
			procHandleClose = dll.NewProc("SpdStorageUnitHandleClose")
			procIoctlOpenDevice = dll.NewProc("SpdIoctlOpenDevice")
			procIoctlProvision = dll.NewProc("SpdIoctlProvision")
			procIoctlTransact = dll.NewProc("SpdIoctlTransact")
			procIoctlUnprovision = dll.NewProc("SpdIoctlUnprovision")
			procVersion = dll.NewProc("SpdVersion")
			return
		}
		dllInitErr = fmt.Errorf("%w — %s", ErrBackendMissing, missingBackendHint())
	})
	return dllInitErr
}

const (
	spdTransactReadKind  = 1
	spdTransactWriteKind = 2
	spdTransactFlushKind = 3
	spdTransactUnmapKind = 4

	defaultHandleDeviceName = "WinSpd.Disk"
	defaultIoctlDeviceName  = "WinSpd"

	maxTransferLen = 64 * 1024 // 64 KiB
)

// ── C-compatible structures ─────────────────────────────────────

// spdStorageUnitParams matches SPD_IOCTL_STORAGE_UNIT_PARAMS (128 bytes).
type spdStorageUnitParams struct {
	Guid                 [16]byte  // 0
	BlockCount           uint64    // 16
	BlockLength          uint32    // 24
	ProductId            [16]byte  // 28
	ProductRevisionLevel [4]byte   // 44
	DeviceType           uint8     // 48
	_                    [3]byte   // 49
	Flags                uint32    // 52  bit0=WriteProtected bit1=CacheSupported bit2=UnmapSupported bit3=EjectDisabled
	MaxTransferLength    uint32    // 56
	_                    [4]byte   // 60
	Reserved             [8]uint64 // 64
}

// spdTransactReq matches SPD_IOCTL_TRANSACT_REQ (32 bytes).
type spdTransactReq struct {
	Hint         uint64  // 0
	Kind         uint8   // 8
	_            [7]byte // 9
	BlockAddress uint64  // 16
	BlockCount   uint32  // 24
	OpFlags      uint32  // 28
}

// spdUnitStatus matches SPD_IOCTL_STORAGE_UNIT_STATUS (32 bytes).
type spdUnitStatus struct {
	ScsiStatus  uint8   // 0
	SenseKey    uint8   // 1
	ASC         uint8   // 2
	ASCQ        uint8   // 3
	_           [4]byte // 4
	Information uint64  // 8
	ReservedCSI uint64  // 16
	ReservedSKS uint32  // 24
	StatusFlags uint32  // 28
}

// spdTransactRsp matches SPD_IOCTL_TRANSACT_RSP (48 bytes).
type spdTransactRsp struct {
	Hint   uint64        // 0
	Kind   uint8         // 8
	_      [7]byte       // 9
	Status spdUnitStatus // 16
}

// ── DLL wrappers ────────────────────────────────────────────────

type spdConn struct {
	closeFn    func() error
	transactFn func(rsp *spdTransactRsp, req *spdTransactReq, buf unsafe.Pointer) error
}

func (c *spdConn) transact(rsp *spdTransactRsp, req *spdTransactReq, buf unsafe.Pointer) error {
	return c.transactFn(rsp, req, buf)
}

func (c *spdConn) close() error {
	if c.closeFn == nil {
		return nil
	}
	return c.closeFn()
}

// spdHandleOpen opens via the Handle API using the global procs.
func spdHandleOpen(params *spdStorageUnitParams) (*spdConn, error) {
	return spdHandleOpenWith(procHandleOpen, procHandleTransact, procHandleClose, params)
}

// spdHandleOpenWith opens via the Handle API using the supplied procs.
// This allows callers to try procs from alternate DLL candidates.
func spdHandleOpenWith(pOpen, pTransact, pClose *windows.LazyProc, params *spdStorageUnitParams) (*spdConn, error) {
	deviceName, err := windows.UTF16PtrFromString(defaultHandleDeviceName)
	if err != nil {
		return nil, fmt.Errorf("handle device name: %w", err)
	}

	var h windows.Handle
	var btl uint32
	r, _, _ := pOpen.Call(
		uintptr(unsafe.Pointer(deviceName)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&btl)),
	)
	if r != 0 {
		return nil, fmt.Errorf("SpdStorageUnitHandleOpen: %w", windows.Errno(r))
	}
	return &spdConn{
		transactFn: func(rsp *spdTransactRsp, req *spdTransactReq, buf unsafe.Pointer) error {
			var rspPtr uintptr
			if rsp != nil {
				rspPtr = uintptr(unsafe.Pointer(rsp))
			}
			r, _, _ := pTransact.Call(
				uintptr(h),
				uintptr(btl),
				rspPtr,
				uintptr(unsafe.Pointer(req)),
				uintptr(buf),
			)
			if r != 0 {
				return fmt.Errorf("SpdStorageUnitHandleTransact: %w", windows.Errno(r))
			}
			return nil
		},
		closeFn: func() error {
			pClose.Call(uintptr(h))
			return nil
		},
	}, nil
}

// spdIoctlOpen opens via the IOCTL API using the global procs.
func spdIoctlOpen(params *spdStorageUnitParams) (*spdConn, error) {
	return spdIoctlOpenWith(procIoctlOpenDevice, procIoctlProvision, procIoctlTransact, procIoctlUnprovision, params)
}

// spdIoctlOpenWith opens via the IOCTL API using the supplied procs.
func spdIoctlOpenWith(pOpen, pProv, pTransact, pUnprov *windows.LazyProc, params *spdStorageUnitParams) (*spdConn, error) {
	deviceName, err := windows.UTF16PtrFromString(defaultIoctlDeviceName)
	if err != nil {
		return nil, fmt.Errorf("ioctl device name: %w", err)
	}

	var device windows.Handle
	r, _, _ := pOpen.Call(
		uintptr(unsafe.Pointer(deviceName)),
		uintptr(unsafe.Pointer(&device)),
	)
	if r != 0 {
		return nil, fmt.Errorf("SpdIoctlOpenDevice: %w", windows.Errno(r))
	}

	var btl uint32
	r, _, _ = pProv.Call(
		uintptr(device),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(&btl)),
	)
	if r != 0 {
		windows.CloseHandle(device)
		return nil, fmt.Errorf("SpdIoctlProvision: %w", windows.Errno(r))
	}

	guid := params.Guid
	return &spdConn{
		transactFn: func(rsp *spdTransactRsp, req *spdTransactReq, buf unsafe.Pointer) error {
			var rspPtr uintptr
			if rsp != nil {
				rspPtr = uintptr(unsafe.Pointer(rsp))
			}
			r, _, _ := pTransact.Call(
				uintptr(device),
				uintptr(btl),
				rspPtr,
				uintptr(unsafe.Pointer(req)),
				uintptr(buf),
			)
			if r != 0 {
				return fmt.Errorf("SpdIoctlTransact: %w", windows.Errno(r))
			}
			return nil
		},
		closeFn: func() error {
			var firstErr error
			if r, _, _ := pUnprov.Call(uintptr(device), uintptr(unsafe.Pointer(&guid))); r != 0 {
				firstErr = fmt.Errorf("SpdIoctlUnprovision: %w", windows.Errno(r))
			}
			if err := windows.CloseHandle(device); err != nil && firstErr == nil {
				firstErr = err
			}
			return firstErr
		},
	}, nil
}

func availableProcSet(procs ...*windows.LazyProc) error {
	for _, proc := range procs {
		if proc == nil {
			return fmt.Errorf("proc not initialized")
		}
		if err := proc.Find(); err != nil {
			return fmt.Errorf("missing %s (%w)", proc.Name, err)
		}
	}
	return nil
}

func detectWinSpdVersion() string {
	if procVersion == nil {
		return "version unavailable"
	}
	if err := procVersion.Find(); err != nil {
		return "version unavailable"
	}
	var version uint32
	r, _, _ := procVersion.Call(uintptr(unsafe.Pointer(&version)))
	if r != 0 {
		return fmt.Sprintf("version unavailable (%v)", windows.Errno(r))
	}
	major := version >> 16
	minor := version & 0xffff
	if major == 0 && minor == 0 {
		return fmt.Sprintf("version 0x%08x", version)
	}
	return fmt.Sprintf("version %d.%d (0x%08x)", major, minor, version)
}

func missingBackendHint() string {
	const spdURL = "https://github.com/winfsp/winspd/releases"

	// Check whether a winspd DLL exists but was renamed (e.g. .bak).
	renamedHint := ""
	if exePath, err := os.Executable(); err == nil {
		matches, _ := filepath.Glob(filepath.Join(filepath.Dir(exePath), "winspd-*.dll.*"))
		if len(matches) > 0 {
			renamedHint = fmt.Sprintf(" (note: %s exists — rename it back to .dll?)", filepath.Base(matches[0]))
		}
	}

	if winfspInstallDir() != "" {
		return fmt.Sprintf(
			"WinFsp is installed but does not include block-device (SPD) support. "+
				"Install the standalone WinSpd driver from %s%s", spdURL, renamedHint)
	}

	if _, found := bundledWinFspDir(); found {
		return fmt.Sprintf(
			"WinFsp runtime files were found nearby but WinFsp alone cannot expose a block device. "+
				"Install the standalone WinSpd driver from %s%s", spdURL, renamedHint)
	}

	return fmt.Sprintf("install the WinSpd driver from %s%s", spdURL, renamedHint)
}

func bundledWinFspDir() (string, bool) {
	dirs := []string{}
	if exePath, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exePath))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}

	seen := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		for _, pattern := range []string{"winfsp-*.dll", "winfsp-*.sys", "winfsp-*.msi", "launchctl-*.exe", "launcher-*.exe"} {
			matches, err := filepath.Glob(filepath.Join(dir, pattern))
			if err == nil && len(matches) > 0 {
				return dir, true
			}
		}
	}
	return "", false
}

// ensureSpdDriverRunning attempts to start the WinSpd/WinFsp kernel driver
// service. WinSpd installs a DLL alongside a kernel driver, but the service
// may not be running (e.g. after install without reboot, or manual stop).
func ensureSpdDriverRunning() error {
	for _, name := range []string{"WinSpd", "WinSpd.Launcher", "WinFsp.Launcher"} {
		out, err := exec.Command("sc", "query", name).CombinedOutput()
		if err != nil {
			continue // service not installed
		}
		if strings.Contains(string(out), "RUNNING") {
			return nil // already running
		}
		if err := exec.Command("sc", "start", name).Run(); err != nil {
			continue
		}
		// Give the driver time to register its device object.
		time.Sleep(2 * time.Second)
		return nil
	}
	return fmt.Errorf("no WinSpd/WinFsp driver service found or could not start (try running as Administrator)")
}

// tryAlternateDLLs attempts to open a WinSpd connection using DLL candidates
// other than the one selected by initSpdDLL. This handles the case where e.g.
// winspd-x64.dll has IOCTL exports but the driver is broken, while
// winfsp-x64.dll has working Handle API exports.
func tryAlternateDLLs(params *spdStorageUnitParams) (*spdConn, error) {
	// Build the same expanded candidate list as initSpdDLL.
	candidates := make([]string, 0, len(spdDLLCandidates)*3)
	for _, name := range spdDLLCandidates {
		candidates = append(candidates, name)
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath) + string(filepath.Separator)
		for _, name := range spdDLLCandidates {
			candidates = append(candidates, exeDir+name)
		}
	}
	if dir := winfspInstallDir(); dir != "" {
		for _, name := range spdDLLCandidates {
			candidates = append(candidates, dir+name)
		}
	}

	for _, name := range candidates {
		if winSpdDLL != nil && winSpdDLL.Name == name {
			continue // already tried this one
		}
		dll := windows.NewLazyDLL(name)
		if err := dll.Load(); err != nil {
			continue
		}

		// Try Handle API from this DLL.
		hOpen := dll.NewProc("SpdStorageUnitHandleOpen")
		hTransact := dll.NewProc("SpdStorageUnitHandleTransact")
		hClose := dll.NewProc("SpdStorageUnitHandleClose")
		if hOpen.Find() == nil && hTransact.Find() == nil && hClose.Find() == nil {
			if conn, err := spdHandleOpenWith(hOpen, hTransact, hClose, params); err == nil {
				return conn, nil
			}
		}

		// Try IOCTL API from this DLL.
		iOpen := dll.NewProc("SpdIoctlOpenDevice")
		iProv := dll.NewProc("SpdIoctlProvision")
		iTrans := dll.NewProc("SpdIoctlTransact")
		iUnprov := dll.NewProc("SpdIoctlUnprovision")
		if iOpen.Find() == nil && iProv.Find() == nil && iTrans.Find() == nil && iUnprov.Find() == nil {
			if conn, err := spdIoctlOpenWith(iOpen, iProv, iTrans, iUnprov, params); err == nil {
				return conn, nil
			}
		}
	}
	return nil, fmt.Errorf("no alternate DLL available")
}

func openWinSpd(params *spdStorageUnitParams) (*spdConn, error) {
	var handleErr, ioctlErr error

	// Try Handle API (new WinSpd / WinFsp 2.0+).
	if availableProcSet(procHandleOpen, procHandleTransact, procHandleClose) == nil {
		conn, err := spdHandleOpen(params)
		if err == nil {
			return conn, nil
		}
		handleErr = err
	} else {
		handleErr = availableProcSet(procHandleOpen, procHandleTransact, procHandleClose)
	}

	// Fall back to IOCTL API (old standalone WinSpd).
	if availableProcSet(procIoctlOpenDevice, procIoctlProvision, procIoctlTransact, procIoctlUnprovision) == nil {
		conn, err := spdIoctlOpen(params)
		if err == nil {
			return conn, nil
		}
		ioctlErr = err

		// IOCTL device open failed — the driver service may not be running.
		// Try to start it and retry once.
		if svcErr := ensureSpdDriverRunning(); svcErr == nil {
			conn, err = spdIoctlOpen(params)
			if err == nil {
				return conn, nil
			}
			ioctlErr = fmt.Errorf("%v (retried after starting service)", err)
		}
	} else {
		ioctlErr = availableProcSet(procIoctlOpenDevice, procIoctlProvision, procIoctlTransact, procIoctlUnprovision)
	}

	// Both API paths failed with the primary DLL.
	// Try alternate DLL candidates (e.g. winfsp-x64.dll when winspd-x64.dll failed).
	if conn, err := tryAlternateDLLs(params); err == nil {
		return conn, nil
	}

	ver := detectWinSpdVersion()
	hint := "install WinFsp 2.0+ from https://github.com/winfsp/winfsp/releases"
	if strings.Contains(ver, "1.0") || strings.Contains(ver, "0x0001") {
		hint = "WinSpd 1.0 is too old and no longer supported; " + hint
	}
	return nil, fmt.Errorf(
		"WinSpd unavailable: handle API: %v; ioctl API: %v; detected %s — %s",
		handleErr,
		ioctlErr,
		ver,
		hint,
	)
}

// ── Session ─────────────────────────────────────────────────────

type winspdSession struct {
	conn    *spdConn
	bd      *BlockDev
	dataBuf []byte
	locker  *autolock.Manager
	stop    chan struct{}
	done    chan struct{}
}

func (s *winspdSession) serve() {
	defer close(s.done)

	var req spdTransactReq
	buf := unsafe.Pointer(&s.dataBuf[0])

	// First transact: no response, just receive the first request.
	if err := s.conn.transact(nil, &req, buf); err != nil {
		return
	}

	for {
		select {
		case <-s.stop:
			return
		default:
		}

		var rsp spdTransactRsp
		rsp.Hint = req.Hint
		rsp.Kind = req.Kind

		switch req.Kind {
		case spdTransactReadKind:
			if s.locker != nil {
				s.locker.Touch()
			}
			off := int64(req.BlockAddress) * int64(s.bd.SectorSize())
			length := int64(req.BlockCount) * int64(s.bd.SectorSize())
			n, err := s.bd.ReadAt(s.dataBuf[:length], off)
			if err != nil {
				rsp.Status.ScsiStatus = 0x02 // CHECK CONDITION
				rsp.Status.SenseKey = 0x03   // MEDIUM ERROR
				rsp.Status.ASC = 0x11        // UNRECOVERED READ ERROR
			}
			rsp.Status.Information = uint64(n)

		case spdTransactWriteKind:
			if s.locker != nil {
				s.locker.Touch()
			}
			off := int64(req.BlockAddress) * int64(s.bd.SectorSize())
			length := int64(req.BlockCount) * int64(s.bd.SectorSize())
			n, err := s.bd.WriteAt(s.dataBuf[:length], off)
			if err != nil {
				rsp.Status.ScsiStatus = 0x02 // CHECK CONDITION
				rsp.Status.SenseKey = 0x03   // MEDIUM ERROR
				rsp.Status.ASC = 0x0C        // WRITE ERROR
			}
			rsp.Status.Information = uint64(n)

		case spdTransactFlushKind:
			if err := s.bd.Flush(); err != nil {
				rsp.Status.ScsiStatus = 0x02
				rsp.Status.SenseKey = 0x04 // HARDWARE ERROR
			}

		case spdTransactUnmapKind:
			// No-op for encrypted containers.

		case 0:
			// Zero kind: device is being torn down.
			return
		}

		if err := s.conn.transact(&rsp, &req, buf); err != nil {
			return
		}
	}
}

func (s *winspdSession) shutdown() error {
	select {
	case <-s.stop:
		// Already stopped.
		return nil
	default:
		close(s.stop)
	}
	if s.locker != nil {
		s.locker.Stop()
	}
	s.bd.Flush()
	closeErr := s.conn.close()
	<-s.done
	return closeErr
}

// LockNow implements autolock.Locker.
func (s *winspdSession) LockNow(reason string) error {
	return s.shutdown()
}

// ── WinSpdBridge (Backend) ──────────────────────────────────────

type WinSpdBridge struct {
	mu     sync.Mutex
	mounts map[string]*winspdSession
}

func (b *WinSpdBridge) Mount(opts Options) error {
	if err := initSpdDLL(); err != nil {
		return err
	}
	if opts.Store == nil {
		return fmt.Errorf("mount: extent store is required")
	}

	bd := NewBlockDev(opts.Store, opts.DiskSizeBytes, opts.ExtentSize)

	var params spdStorageUnitParams
	params.Guid = guidFromPath(opts.ContainerPath)
	params.BlockCount = opts.DiskSizeBytes / sectorSize
	params.BlockLength = sectorSize
	params.MaxTransferLength = maxTransferLen
	params.Flags = 0x02 // CacheSupported
	copy(params.ProductId[:], "ECDISK")
	copy(params.ProductRevisionLevel[:], "1.0")

	// Snapshot existing physical drives so we can detect the new one.
	before := listPhysicalDrives()

	conn, err := openWinSpd(&params)
	if err != nil {
		return err
	}

	sess := &winspdSession{
		conn:    conn,
		bd:      bd,
		dataBuf: make([]byte, maxTransferLen),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	if opts.IdleSeconds > 0 {
		sess.locker = autolock.New(sess, time.Duration(opts.IdleSeconds)*time.Second)
		go sess.locker.Run(5 * time.Second)
	}

	b.mu.Lock()
	if b.mounts == nil {
		b.mounts = make(map[string]*winspdSession)
	}
	b.mounts[opts.MountPoint] = sess
	b.mu.Unlock()

	// Start serving I/O requests in the background.
	go sess.serve()

	// Best-effort: bring the new disk online and assign the requested drive letter.
	if letter := parseDriveLetter(opts.MountPoint); letter != "" {
		if err := onlineDisk(before, letter); err != nil {
			fmt.Fprintf(os.Stderr, "note: auto-assign %s: failed (%v) — use Disk Management\n", opts.MountPoint, err)
		}
	}

	return nil
}

func (b *WinSpdBridge) Unmount(mountPoint string) error {
	b.mu.Lock()
	sess, ok := b.mounts[mountPoint]
	if !ok {
		b.mu.Unlock()
		return fmt.Errorf("no active mount at %s", mountPoint)
	}
	delete(b.mounts, mountPoint)
	b.mu.Unlock()

	// Offline the disk before tearing down the backend.
	if letter := parseDriveLetter(mountPoint); letter != "" {
		offlineDisk(letter)
	}

	return sess.shutdown()
}

// ── Helpers ─────────────────────────────────────────────────────

// guidFromPath derives a deterministic v4-style GUID from the container path
// so that re-mounting the same container reuses the same SCSI identity.
func guidFromPath(path string) [16]byte {
	h := sha256.Sum256([]byte(strings.ToLower(path)))
	var g [16]byte
	copy(g[:], h[:16])
	g[6] = (g[6] & 0x0f) | 0x40 // version 4
	g[8] = (g[8] & 0x3f) | 0x80 // variant 1
	return g
}

func parseDriveLetter(mp string) string {
	s := strings.TrimSuffix(strings.ToUpper(NormalizeMountPoint(mp)), ":")
	if len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' {
		return s
	}
	return ""
}

// listPhysicalDrives returns the set of currently visible PhysicalDrive numbers.
func listPhysicalDrives() map[uint32]bool {
	m := make(map[uint32]bool)
	for i := uint32(0); i < 128; i++ {
		p, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\PhysicalDrive%d`, i))
		h, err := windows.CreateFile(p, 0,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			windows.CloseHandle(h)
			m[i] = true
		}
	}
	return m
}

// onlineDisk waits for a new physical drive to appear, brings it online,
// and assigns the requested drive letter. For a fresh (RAW) disk it also
// initialises GPT + NTFS; for an existing disk it just remaps the letter.
func onlineDisk(before map[uint32]bool, letter string) error {
	var diskNum uint32
	found := false
	for attempt := 0; attempt < 20; attempt++ {
		time.Sleep(500 * time.Millisecond)
		for n := uint32(0); n < 128; n++ {
			if before[n] {
				continue
			}
			p, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\PhysicalDrive%d`, n))
			h, err := windows.CreateFile(p, 0,
				windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
				nil, windows.OPEN_EXISTING, 0, 0)
			if err == nil {
				windows.CloseHandle(h)
				diskNum = n
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return fmt.Errorf("disk did not appear within 10 s")
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$d = Get-Disk -Number %[1]d
if ($d.IsOffline)   { Set-Disk -Number %[1]d -IsOffline  $false }
if ($d.IsReadOnly)  { Set-Disk -Number %[1]d -IsReadOnly $false }
if ($d.PartitionStyle -eq 'RAW') {
    Initialize-Disk -Number %[1]d -PartitionStyle GPT -Confirm:$false
    New-Partition -DiskNumber %[1]d -UseMaximumSize -DriveLetter %[2]s |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel ECDISK -Confirm:$false | Out-Null
} else {
    $p = Get-Partition -DiskNumber %[1]d |
         Where-Object { $_.Type -ne 'Reserved' -and $_.Type -ne 'System' } |
         Select-Object -First 1
    if ($p) {
        Set-Partition -DiskNumber %[1]d -PartitionNumber $p.PartitionNumber -NewDriveLetter %[2]s
    }
}`, diskNum, letter)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// offlineDisk takes the volume offline before WinSpd device removal.
func offlineDisk(letter string) {
	script := fmt.Sprintf(`
$p = Get-Partition -DriveLetter %s -ErrorAction SilentlyContinue
if ($p) { Set-Disk -Number $p.DiskNumber -IsOffline $true }`, letter)
	exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Run()
}
