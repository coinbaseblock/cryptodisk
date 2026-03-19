//go:build windows

package mount

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"ecdisk/internal/autolock"
)

// ── WinSpd DLL bindings ─────────────────────────────────────────

var (
	winSpdDLL = windows.NewLazyDLL("winspd-x64.dll")

	procHandleOpen     = winSpdDLL.NewProc("SpdStorageUnitHandleOpen")
	procHandleTransact = winSpdDLL.NewProc("SpdStorageUnitHandleTransact")
	procHandleClose    = winSpdDLL.NewProc("SpdStorageUnitHandleClose")

	procIoctlOpenDevice  = winSpdDLL.NewProc("SpdIoctlOpenDevice")
	procIoctlProvision   = winSpdDLL.NewProc("SpdIoctlProvision")
	procIoctlTransact    = winSpdDLL.NewProc("SpdIoctlTransact")
	procIoctlUnprovision = winSpdDLL.NewProc("SpdIoctlUnprovision")

	procVersion = winSpdDLL.NewProc("SpdVersion")
)

const (
	spdTransactReadKind  = 1
	spdTransactWriteKind = 2
	spdTransactFlushKind = 3
	spdTransactUnmapKind = 4

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

func spdHandleOpen(params *spdStorageUnitParams) (*spdConn, error) {
	var h windows.Handle
	var btl uint32
	r, _, _ := procHandleOpen.Call(
		0, // NULL → default device name "WinSpd.Disk"
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
			r, _, _ := procHandleTransact.Call(
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
			procHandleClose.Call(uintptr(h))
			return nil
		},
	}, nil
}

func spdIoctlOpen(params *spdStorageUnitParams) (*spdConn, error) {
	var device windows.Handle
	r, _, _ := procIoctlOpenDevice.Call(
		0, // NULL → default device name "WinSpd"
		uintptr(unsafe.Pointer(&device)),
	)
	if r != 0 {
		return nil, fmt.Errorf("SpdIoctlOpenDevice: %w", windows.Errno(r))
	}

	var btl uint32
	r, _, _ = procIoctlProvision.Call(
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
			r, _, _ := procIoctlTransact.Call(
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
			if r, _, _ := procIoctlUnprovision.Call(uintptr(device), uintptr(unsafe.Pointer(&guid))); r != 0 {
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
		if err := proc.Find(); err != nil {
			return fmt.Errorf("missing %s (%w)", proc.Name, err)
		}
	}
	return nil
}

func detectWinSpdVersion() string {
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

func openWinSpd(params *spdStorageUnitParams) (*spdConn, error) {
	if err := availableProcSet(procHandleOpen, procHandleTransact, procHandleClose); err == nil {
		return spdHandleOpen(params)
	}
	if err := availableProcSet(procIoctlOpenDevice, procIoctlProvision, procIoctlTransact, procIoctlUnprovision); err == nil {
		return spdIoctlOpen(params)
	}

	handleErr := availableProcSet(procHandleOpen, procHandleTransact, procHandleClose)
	ioctlErr := availableProcSet(procIoctlOpenDevice, procIoctlProvision, procIoctlTransact, procIoctlUnprovision)
	return nil, fmt.Errorf(
		"winspd-x64.dll is incompatible: handle API %v; ioctl API %v; detected %s — install a WinSpd build that exports either API from github.com/winfsp/winspd",
		handleErr,
		ioctlErr,
		detectWinSpdVersion(),
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
	if err := winSpdDLL.Load(); err != nil {
		return fmt.Errorf("%w (install WinSpd driver from github.com/winfsp/winspd)", ErrBackendMissing)
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
	s := strings.TrimSuffix(strings.ToUpper(mp), ":")
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
