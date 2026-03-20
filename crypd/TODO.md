# CrypD — GUI Encrypted Disk Manager

## Project Status: Prototype

โปรเจค GUI แยกจาก ecdisk (CLI) เพื่อให้ใช้งานง่ายผ่าน Fyne GUI framework

---

## สิ่งที่ทำเสร็จแล้ว

- [x] แยกโครงสร้างโปรเจค crypd/ ออกจาก ecdisk
- [x] Copy core packages: cryptovault, container, cache, autolock, vhdx, mount
- [x] สร้าง go.mod แยกสำหรับ crypd (module crypd)
- [x] อัปเดต import paths ทั้งหมดจาก `ecdisk/internal/` → `crypd/internal/`
- [x] สร้าง GUI entry point (cmd/crypd/main.go)
- [x] สร้าง GUI layer ด้วย Fyne framework (internal/app/gui.go)
  - Tab: Container (Create, Inspect, Change Password, Recover)
  - Tab: VHDX (Create, Differencing)
  - Tab: Mount / Unmount
- [x] Status bar แสดงสถานะการทำงาน

---

## TODO — สิ่งที่ต้องทำต่อ

### Priority 1: ทำให้ build ได้

- [ ] รัน `go mod tidy` ใน crypd/ เพื่อ resolve dependencies ทั้งหมด
- [ ] แก้ไข compile errors ที่อาจเกิดจาก Fyne version mismatch
- [ ] ทดสอบ build: `cd crypd && go build ./cmd/crypd`
- [ ] ติดตั้ง Fyne dependencies สำหรับ OS (Linux: libgl1-mesa-dev, xorg-dev)

### Priority 2: GUI Improvements

- [ ] เพิ่ม File Dialog (เลือกไฟล์ด้วย Browse button แทนพิมพ์ path)
- [ ] เพิ่ม Progress Bar สำหรับ operations ที่ใช้เวลานาน (create, mount)
- [ ] ทำ async operations ด้วย goroutine เพื่อไม่ให้ UI ค้าง
- [ ] เพิ่ม confirmation dialog ก่อน destructive operations
- [ ] เพิ่ม password strength indicator
- [ ] เพิ่ม password confirmation field (type password twice)
- [ ] Dark/Light theme toggle

### Priority 3: Features

- [ ] เพิ่ม Backend Doctor tab (Windows)
- [ ] เพิ่ม Repair Backend tab (Windows)
- [ ] แสดง mounted containers list (สถานะ mount ปัจจุบัน)
- [ ] เพิ่ม system tray icon (minimize to tray)
- [ ] เพิ่ม auto-lock notification (แจ้งเตือนก่อน idle timeout)
- [ ] เพิ่ม drag & drop container file
- [ ] เพิ่ม recent containers list
- [ ] เพิ่ม keyboard shortcuts

### Priority 4: Testing & Quality

- [ ] เขียน unit tests สำหรับ GUI logic (แยก business logic จาก UI)
- [ ] เพิ่ม integration tests
- [ ] ทดสอบบน Windows, Linux, macOS
- [ ] เพิ่ม CI/CD pipeline
- [ ] เพิ่ม app icon / branding

### Priority 5: Distribution

- [ ] สร้าง Makefile สำหรับ build cross-platform
- [ ] Package เป็น .exe (Windows), .AppImage (Linux), .app (macOS)
- [ ] สร้าง installer (NSIS/WiX สำหรับ Windows)
- [ ] Auto-update mechanism
- [ ] Code signing

---

## โครงสร้างโปรเจค

```
crypd/
├── cmd/crypd/main.go          ← GUI entry point
├── go.mod                     ← module crypd (แยกจาก ecdisk)
├── internal/
│   ├── app/
│   │   ├── gui.go             ← Fyne GUI (แทน CLI menu)
│   │   └── util.go            ← helper functions
│   ├── cryptovault/           ← crypto header & extent (copy จาก ecdisk)
│   ├── container/             ← container lifecycle (copy จาก ecdisk)
│   ├── mount/                 ← mount backends (copy จาก ecdisk)
│   ├── cache/                 ← write-back cache (copy จาก ecdisk)
│   ├── autolock/              ← idle auto-lock (copy จาก ecdisk)
│   └── vhdx/                  ← VHDX creation (copy จาก ecdisk)
└── TODO.md                    ← ไฟล์นี้
```

## วิธี Build

```bash
# ติดตั้ง Fyne dependencies (Linux)
sudo apt install -y libgl1-mesa-dev xorg-dev

# Build
cd crypd
go mod tidy
go build -o crypd ./cmd/crypd

# Run
./crypd
```

## หมายเหตุ

- Core packages (cryptovault, container, mount, cache, autolock, vhdx) copy มาจาก ecdisk
  เมื่อ ecdisk อัปเดต ให้ sync กลับมาที่นี่ด้วย
- GUI ใช้ Fyne v2 (cross-platform: Windows, Linux, macOS)
- ในอนาคตอาจพิจารณาย้ายไปใช้ Wails (web-based UI) ถ้าต้องการ UI ที่ซับซ้อนกว่านี้
