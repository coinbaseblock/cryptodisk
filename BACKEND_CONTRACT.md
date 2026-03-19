# ecdiskd backend contract

This file defines the intended backend contract for a future WinSpd-based helper.

## Purpose

The Go CLI should remain responsible for:
- password prompt and policy
- header parsing and unlock policy
- recovery and password change
- container metadata changes

The backend helper should remain responsible for:
- exposing a block device to Windows
- lazy extent reads
- write-back cache
- flush and detach
- idle disconnect / force lock

## Proposed model

The easiest first production step is a local-only helper process or Windows service:

```text
ecdisk.exe (CLI)
  -> validates password
  -> starts ecdiskd.exe
  -> passes container path, mountpoint, idle/cache policy over named pipe

ecdiskd.exe (WinSpd block server)
  -> opens container
  -> unwraps master key or receives a sealed session key token
  -> services read/write/flush/unmap requests
```

## Recommended IPC

- Named pipe on Windows with ACL limited to the current user/session.
- Avoid passing plaintext password on the command line.
- Prefer one of these:
  1. CLI sends password over named pipe; daemon derives KEK itself.
  2. CLI unwraps master key, then wraps it under a short-lived session key and sends that.

## Read path

1. Windows requests LBA range.
2. Backend resolves LBA -> extent numbers.
3. Cache hit: return plaintext block slice from cached extent.
4. Cache miss: read ciphertext extent from container, decrypt, cache, return requested block slice.

## Write path

1. Windows writes LBA range.
2. Backend loads affected extent(s).
3. Modify plaintext pages in memory.
4. Mark dirty in cache.
5. Flush on timer, cache pressure, explicit flush, unmount, or auto-lock.

## Auto-lock

- Track last I/O timestamp.
- On idle timeout:
  - flush dirty extents
  - zero master key
  - detach block device
  - exit helper or park in locked state

## Recovery model

Recovery remains entirely in the CLI/control plane and does not require the backend.
