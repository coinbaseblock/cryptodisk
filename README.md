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

It does **not** yet include the final pure-Go Windows block device server needed to expose the decrypted container as a mounted drive letter. That part needs either:

1. a WinSpd integration layer written in Go/CGO, or
2. a file-system approach such as WinFsp/go-winfsp instead of a block-device mount.
