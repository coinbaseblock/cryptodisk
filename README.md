# ecdisk prototype

Go-first prototype for a custom encrypted disk container with a VHDX helper layer.

## What changed in this build

- The canonical CLI entrypoint is `cmd/ecdisk/main.go`, so the recommended build command is `go build -o ecdisk.exe ./cmd/ecdisk`.
- The repository root still has a thin `main.go` convenience wrapper, but building the explicit `./cmd/ecdisk` package is more robust if your checkout contains extra stray `.go` files.
- Usage examples are plain executable invocations only. No `.sh`, `.cmd`, or PowerShell scripts are required.
- The current build is still **pure Go for the CLI/control plane**, but the actual custom block-device mount backend is **not implemented yet** in this prototype.

## Build

```text
go mod tidy
go build -o ecdisk.exe ./cmd/ecdisk
```


## Build troubleshooting

If Windows reports an error like:

```text
found packages main (main.go) and mount (winspd_bridge_windows.go) in C:\system\cryptodisk
```

then your working tree has a misplaced `winspd_bridge_windows.go` file at the repository root. In this repo that file belongs under `internal/mount/`, not next to `main.go`. The fastest workaround is to build the explicit CLI package instead of the repo root:

```text
go build -o ecdisk.exe ./cmd/ecdisk
```

If the misplaced file is part of your checkout, move or delete the stray root-level copy and restore the normal directory structure before rebuilding.

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

Also note that **DiskSpd is not WinSpd**. Installing the `Microsoft.DiskSpd` winget package gives you the DiskSpd storage benchmark (`diskspd.exe`), not the WinSpd block-device backend that ecdisk needs for mounting.

The interactive menu still shows mount/unmount on Windows now, so you can enter the container path and receive the exact backend error instead of being blocked before the check runs.

This build also adds:

- `backend-doctor` to print a step-by-step diagnostic of the current WinFsp / WinSpd state.
- `repair-backend` to stop old services, remove stale registrations, optionally reinstall WinFsp from a local MSI (or a directory containing one), optionally redeploy WinSpd from a local extracted payload directory or WinSpd MSI, and print where the process failed if anything is still wrong.
- Interactive menu option `10` (`Repair Mount Backend`) as a guided wrapper around the same repair flow.

Example repair flow:

```text
ecdisk.exe backend-doctor
ecdisk.exe repair-backend --winfsp-installer C:\installers\winfsp.msi --winspd-dir C:\installers\winspd --script-out C:\temp\repair-ecdisk-backend.ps1
# or point at a folder that contains winfsp-*.msi
ecdisk.exe repair-backend --winfsp-installer C:\installers --winspd-dir C:\installers\winspd
```

`--winspd-dir` now accepts either an extracted WinSpd payload directory or a WinSpd `.msi` package. When you pass a directory, it should contain the files from a matching WinSpd package, including `devsetup-*.exe`, at least one `winspd-*.dll`, and the driver `.inf` file. The repair command will report the exact missing file when the directory or extracted MSI contents are incomplete.

All other features (create, inspect, change password, recover, VHDX creation) work independently of WinSpd.

**Possible future directions:**
- Track future WinFsp releases in case SPD support is added later: <https://github.com/winfsp/winfsp/releases>
- An alternative approach could use WinFsp/go-winfsp to present the container as a file system rather than a block device
- A helper daemon approach as described in `BACKEND_CONTRACT.md`
