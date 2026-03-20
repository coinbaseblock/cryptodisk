# ecdisk prototype

Go-first prototype for a custom encrypted disk container with a VHDX helper layer.

## What changed in this build

- `go build .` now works from the project root because the root now has a `main.go`.
- There is still a second entrypoint at `cmd/ecdisk/main.go`, but it is only a thin wrapper.
- Usage examples are plain executable invocations only. No `.sh`, `.cmd`, or PowerShell scripts are required.
- The current build is still **pure Go for the CLI/control plane**, but the actual custom block-device mount backend is **not implemented yet** in this prototype.

## Build

```text
go mod tidy
go build -o ecdisk.exe .
```

## CLI usage

```text
ecdisk.exe init --container D:\vault.ecd --size-gb 20 --extent-mb 4
ecdisk.exe inspect --container D:\vault.ecd
ecdisk.exe passwd --container D:\vault.ecd
ecdisk.exe recover --container D:\vault.ecd --recovery ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456

ecdisk.exe mkvhdx --path D:\blank.vhdx --size-gb 20 --block-mb 4
ecdisk.exe diffvhdx --base D:\base.vhdx --path D:\child.vhdx --block-mb 4

ecdisk.exe mount --container D:\vault.ecd --mount X:
ecdisk.exe unmount --mount X:
ecdisk.exe backend-doctor
ecdisk.exe repair-backend --winfsp-installer C:\installers\winfsp.msi --winspd-dir C:\installers\winspd
```

## Programmatic usage from Go

```go
package main

import (
    "fmt"
    "log"

    "ecdisk/internal/container"
)

func main() {
    recoveryKey, err := container.Create(`D:\vault.ecd`, "StrongPassword123!", 20*1024*1024*1024, 4*1024*1024)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("recovery key:", recoveryKey)

    h, err := container.OpenWithPassword(`D:\vault.ecd`, "StrongPassword123!")
    if err != nil {
        log.Fatal(err)
    }
    defer h.Close()

    fmt.Println("extent size:", h.Header.ExtentSize)
}
```

## Important limitation

This prototype currently includes:

- custom header format
- Argon2id password KDF
- master-key wrapping
- recovery-key wrapping
- password rewrap without re-encrypting the payload
- encrypted extent read/write primitives
- VHDX create / differencing wrappers via `go-winio`

### Mount/Unmount on Windows (backend-dependent)

The mount/unmount commands (`mount`, `unmount`, menu options 7/8) require a **WinSpd** (Storage Proxy Driver) compatible kernel driver and DLL. WinSpd was a separate project from WinFsp — WinFsp handles file systems while WinSpd handles block devices.

**However**, the standalone WinSpd project (<https://github.com/winfsp/winspd>) is **no longer actively maintained** and its release assets may be unavailable for download. Because of that, Windows mount/unmount remains **backend-dependent** and may fail at runtime unless a compatible WinSpd-style driver and DLL are present.

WinFsp alone (including WinFsp 2.1.25156 and its `winfsp-*.dll` files) is **not** sufficient for mounting because it does not export the SPD symbols needed by ecdisk.

The interactive menu still shows mount/unmount on Windows now, so you can enter the container path and receive the exact backend error instead of being blocked before the check runs.

This build also adds:

- `backend-doctor` to print a step-by-step diagnostic of the current WinFsp / WinSpd state.
- `repair-backend` to stop old services, remove stale registrations, optionally reinstall WinFsp from a local MSI (or a directory containing one), optionally redeploy WinSpd from a local extracted payload directory, and print where the process failed if anything is still wrong.
- Interactive menu option `9` (`Repair Mount Backend`) as a guided wrapper around the same repair flow.

Example repair flow:

```text
ecdisk.exe backend-doctor
ecdisk.exe repair-backend --winfsp-installer C:\installers\winfsp.msi --winspd-dir C:\installers\winspd --script-out C:\temp\repair-ecdisk-backend.ps1
# or point at a folder that contains winfsp-*.msi
ecdisk.exe repair-backend --winfsp-installer C:\installers --winspd-dir C:\installers\winspd
```

The WinSpd payload directory should contain the files from a matching WinSpd package, including `devsetup-*.exe`, at least one `winspd-*.dll`, and the driver `.inf` file. The repair command will report the exact missing file when the directory is incomplete.

All other features (create, inspect, change password, recover, VHDX creation) work independently of WinSpd.

**Possible future directions:**
- Track future WinFsp releases in case SPD support is added later: <https://github.com/winfsp/winfsp/releases>
- An alternative approach could use WinFsp/go-winfsp to present the container as a file system rather than a block device
- A helper daemon approach as described in `BACKEND_CONTRACT.md`
