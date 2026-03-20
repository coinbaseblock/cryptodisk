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

### Mount/Unmount on Windows (currently unavailable)

The mount/unmount commands (`mount`, `unmount`, menu options 7/8) require a **WinSpd** (Storage Proxy Driver) compatible kernel driver and DLL. WinSpd was a separate project from WinFsp — WinFsp handles file systems while WinSpd handles block devices.

**However**, the standalone WinSpd project (<https://github.com/winfsp/winspd>) is **no longer actively maintained** and its release assets may be unavailable for download. This means mount/unmount functionality on Windows is **not currently usable** in a straightforward way.

WinFsp alone (winfsp-x64.dll) is **not** sufficient for mounting because it does not export the SPD symbols needed by ecdisk.

All other features (create, inspect, change password, recover, VHDX creation) work independently of WinSpd.

**Possible future directions:**
- A future WinFsp release may integrate SPD support — check <https://github.com/winfsp/winfsp/releases>
- An alternative approach could use WinFsp/go-winfsp to present the container as a file system rather than a block device
- A helper daemon approach as described in `BACKEND_CONTRACT.md`
