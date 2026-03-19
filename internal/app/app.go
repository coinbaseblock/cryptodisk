package app

import (
    "bufio"
    "errors"
    "flag"
    "fmt"
    "os"
    "strings"

    "ecdisk/internal/container"
    "ecdisk/internal/cryptovault"
    "ecdisk/internal/mount"
    "ecdisk/internal/vhdx"
)

func Main() {
    if len(os.Args) < 2 {
        usage()
        os.Exit(2)
    }
    var err error
    switch os.Args[1] {
    case "init":
        err = cmdInit(os.Args[2:])
    case "inspect":
        err = cmdInspect(os.Args[2:])
    case "passwd":
        err = cmdPasswd(os.Args[2:])
    case "recover":
        err = cmdRecover(os.Args[2:])
    case "mkvhdx":
        err = cmdMkVHDX(os.Args[2:])
    case "diffvhdx":
        err = cmdDiffVHDX(os.Args[2:])
    case "mount":
        err = cmdMount(os.Args[2:])
    case "unmount":
        err = cmdUnmount(os.Args[2:])
    default:
        usage()
        os.Exit(2)
    }
    if err != nil {
        fmt.Fprintln(os.Stderr, "error:", err)
        os.Exit(1)
    }
}

func usage() {
    fmt.Println(`ecdisk commands:
  init      --container FILE --size-gb N [--extent-mb 4]
  inspect   --container FILE
  passwd    --container FILE
  recover   --container FILE --recovery KEY
  mkvhdx    --path FILE --size-gb N [--block-mb 4]
  diffvhdx  --base FILE --path FILE [--block-mb 4]
  mount     --container FILE --mount X: [--idle-seconds 900 --cache-extents 128]
  unmount   --mount X:`)
}

func cmdInit(args []string) error {
    fs := flag.NewFlagSet("init", flag.ContinueOnError)
    containerPath := fs.String("container", "", "container path")
    sizeGB := fs.Uint64("size-gb", 0, "logical disk size in GB")
    extentMB := fs.Uint64("extent-mb", 4, "encrypted extent size in MB")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *containerPath == "" || *sizeGB == 0 {
        return errors.New("--container and --size-gb are required")
    }
    pw, err := prompt("new password: ")
    if err != nil {
        return err
    }
    recoveryKey, err := container.Create(*containerPath, pw, *sizeGB*1024*1024*1024, uint32(*extentMB*1024*1024))
    if err != nil {
        return err
    }
    fmt.Println("container created:", *containerPath)
    fmt.Println("recovery key:", recoveryKey)
    fmt.Println("store the recovery key offline")
    return nil
}

func cmdInspect(args []string) error {
    fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
    containerPath := fs.String("container", "", "container path")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *containerPath == "" {
        return errors.New("--container is required")
    }
    f, err := os.Open(*containerPath)
    if err != nil {
        return err
    }
    defer f.Close()
    hdr, err := cryptovault.ParseHeader(f)
    if err != nil {
        return err
    }
    fmt.Printf("magic: %s\n", hdr.Magic)
    fmt.Printf("version: %d\n", hdr.Version)
    fmt.Printf("disk size bytes: %d\n", hdr.DiskSizeBytes)
    fmt.Printf("extent size bytes: %d\n", hdr.ExtentSize)
    fmt.Printf("argon2 time: %d\n", hdr.KDF.Time)
    fmt.Printf("argon2 memory KiB: %d\n", hdr.KDF.Memory)
    fmt.Printf("argon2 threads: %d\n", hdr.KDF.Threads)
    fmt.Printf("wrapped master key bytes: %d\n", len(hdr.WrappedMasterKey))
    fmt.Printf("wrapped recovery key bytes: %d\n", len(hdr.WrappedMasterKeyRecovery))
    return nil
}

func cmdPasswd(args []string) error {
    fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
    containerPath := fs.String("container", "", "container path")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *containerPath == "" {
        return errors.New("--container is required")
    }
    oldPw, err := prompt("current password: ")
    if err != nil {
        return err
    }
    h, err := container.OpenWithPassword(*containerPath, oldPw)
    if err != nil {
        return err
    }
    defer h.Close()
    newPw, err := prompt("new password: ")
    if err != nil {
        return err
    }
    if err := h.ChangePassword(newPw); err != nil {
        return err
    }
    fmt.Println("password changed by rewrapping master key only")
    return nil
}

func cmdRecover(args []string) error {
    fs := flag.NewFlagSet("recover", flag.ContinueOnError)
    containerPath := fs.String("container", "", "container path")
    recoveryKey := fs.String("recovery", "", "recovery key")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *containerPath == "" || *recoveryKey == "" {
        return errors.New("--container and --recovery are required")
    }
    h, err := container.OpenWithRecovery(*containerPath, *recoveryKey)
    if err != nil {
        return err
    }
    defer h.Close()
    newPw, err := prompt("new password: ")
    if err != nil {
        return err
    }
    if err := h.ChangePassword(newPw); err != nil {
        return err
    }
    fmt.Println("password rewrapped from recovery key")
    return nil
}

func cmdMkVHDX(args []string) error {
    fs := flag.NewFlagSet("mkvhdx", flag.ContinueOnError)
    path := fs.String("path", "", "vhdx path")
    sizeGB := fs.Uint("size-gb", 0, "size in GB")
    blockMB := fs.Uint("block-mb", 4, "block size in MB")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *path == "" || *sizeGB == 0 {
        return errors.New("--path and --size-gb are required")
    }
    return vhdx.Create(*path, uint32(*sizeGB), uint32(*blockMB))
}

func cmdDiffVHDX(args []string) error {
    fs := flag.NewFlagSet("diffvhdx", flag.ContinueOnError)
    path := fs.String("path", "", "child vhdx path")
    base := fs.String("base", "", "base vhdx path")
    blockMB := fs.Uint("block-mb", 4, "block size in MB")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *path == "" || *base == "" {
        return errors.New("--path and --base are required")
    }
    return vhdx.CreateDiff(*path, *base, uint32(*blockMB))
}

func cmdMount(args []string) error {
    fs := flag.NewFlagSet("mount", flag.ContinueOnError)
    containerPath := fs.String("container", "", "container path")
    mountPoint := fs.String("mount", "", "mount point, e.g. X:")
    idleSeconds := fs.Int("idle-seconds", 900, "auto-lock after idle seconds")
    cacheExtents := fs.Int("cache-extents", 128, "write-back cache size in extents")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *containerPath == "" || *mountPoint == "" {
        return errors.New("--container and --mount are required")
    }
    pw, err := prompt("password: ")
    if err != nil {
        return err
    }
    h, err := container.OpenWithPassword(*containerPath, pw)
    if err != nil {
        return err
    }
    defer h.Close()

    backend := mount.DefaultBackend()
    err = backend.Mount(mount.Options{
        ContainerPath: *containerPath,
        MountPoint:    strings.ToUpper(*mountPoint),
        IdleSeconds:   *idleSeconds,
        CacheExtents:  *cacheExtents,
    })
    if errors.Is(err, mount.ErrBackendMissing) {
        return fmt.Errorf("password ok, but mount backend is not implemented in this build yet")
    }
    return err
}

func cmdUnmount(args []string) error {
    fs := flag.NewFlagSet("unmount", flag.ContinueOnError)
    mountPoint := fs.String("mount", "", "mount point, e.g. X:")
    if err := fs.Parse(args); err != nil {
        return err
    }
    if *mountPoint == "" {
        return errors.New("--mount is required")
    }
    return mount.DefaultBackend().Unmount(strings.ToUpper(*mountPoint))
}

func prompt(label string) (string, error) {
    fmt.Fprint(os.Stderr, label)
    br := bufio.NewReader(os.Stdin)
    s, err := br.ReadString('\n')
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(s), nil
}
