package app

import (
	"fmt"
	"strconv"

	"fyne.io/fyne/v2"
	fyneApp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"crypd/internal/cache"
	cont "crypd/internal/container"
	"crypd/internal/cryptovault"
	"crypd/internal/mount"
	"crypd/internal/vhdx"
)

// RunGUI launches the Fyne-based graphical interface.
func RunGUI() {
	a := fyneApp.NewWithID("com.crypd.app")
	a.Settings().SetTheme(theme.DarkTheme())

	w := a.NewWindow("CrypD — Encrypted Disk Manager")
	w.Resize(fyne.NewSize(720, 520))

	statusLabel := widget.NewLabel("Ready")
	statusLabel.Wrapping = fyne.TextWrapWord

	setStatus := func(msg string) {
		statusLabel.SetText(msg)
	}

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Container", theme.FolderIcon(), buildContainerTab(w, setStatus)),
		container.NewTabItemWithIcon("VHDX", theme.StorageIcon(), buildVHDXTab(w, setStatus)),
		container.NewTabItemWithIcon("Mount", theme.ComputerIcon(), buildMountTab(w, setStatus)),
	)
	tabs.SetTabLocation(container.TabLocationLeading)

	statusBar := container.NewHBox(
		widget.NewIcon(theme.InfoIcon()),
		statusLabel,
		layout.NewSpacer(),
		widget.NewLabel("CrypD v1.0"),
	)

	content := container.NewBorder(nil, statusBar, nil, nil, tabs)
	w.SetContent(content)
	w.ShowAndRun()
}

// ─── Container Tab ──────────────────────────────────────────────────

func buildContainerTab(w fyne.Window, setStatus func(string)) fyne.CanvasObject {
	// Create Container section
	createPath := widget.NewEntry()
	createPath.SetPlaceHolder("/path/to/container.ecd")
	createSizeGB := widget.NewEntry()
	createSizeGB.SetPlaceHolder("10")
	createExtentMB := widget.NewEntry()
	createExtentMB.SetPlaceHolder("4")
	createExtentMB.SetText("4")
	createPassword := widget.NewPasswordEntry()
	createPassword.SetPlaceHolder("Password")

	createBtn := widget.NewButtonWithIcon("Create Container", theme.ContentAddIcon(), func() {
		path := createPath.Text
		sizeStr := createSizeGB.Text
		pw := createPassword.Text
		extStr := createExtentMB.Text

		if path == "" || sizeStr == "" || pw == "" {
			dialog.ShowError(fmt.Errorf("container path, size, and password are required"), w)
			return
		}
		sizeGB, err := strconv.ParseUint(sizeStr, 10, 64)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid size: %v", err), w)
			return
		}
		extentMB, err := strconv.ParseUint(extStr, 10, 32)
		if err != nil {
			extentMB = 4
		}

		setStatus("Creating container...")
		recoveryKey, err := cont.Create(path, pw, sizeGB*1024*1024*1024, uint32(extentMB*1024*1024))
		if err != nil {
			dialog.ShowError(err, w)
			setStatus("Create failed: " + err.Error())
			return
		}
		setStatus("Container created!")
		dialog.ShowInformation("Container Created",
			fmt.Sprintf("Container: %s\n\nRecovery Key:\n%s\n\nStore this key offline!", path, recoveryKey), w)
	})
	createBtn.Importance = widget.HighImportance

	createForm := container.NewVBox(
		widget.NewLabelWithStyle("Create New Container", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Container Path:"), createPath,
		widget.NewLabel("Disk Size (GB):"), createSizeGB,
		widget.NewLabel("Extent Size (MB):"), createExtentMB,
		widget.NewLabel("Password:"), createPassword,
		createBtn,
	)

	// Inspect section
	inspectPath := widget.NewEntry()
	inspectPath.SetPlaceHolder("/path/to/container.ecd")
	inspectResult := widget.NewMultiLineEntry()
	inspectResult.Disable()
	inspectResult.SetMinRowsVisible(8)

	inspectBtn := widget.NewButtonWithIcon("Inspect", theme.SearchIcon(), func() {
		path := inspectPath.Text
		if path == "" {
			dialog.ShowError(fmt.Errorf("container path is required"), w)
			return
		}
		setStatus("Inspecting...")
		f, err := openFile(path)
		if err != nil {
			dialog.ShowError(err, w)
			setStatus("Inspect failed")
			return
		}
		defer f.Close()

		hdr, err := cryptovault.ParseHeader(f)
		if err != nil {
			dialog.ShowError(err, w)
			setStatus("Inspect failed")
			return
		}
		info := fmt.Sprintf("Magic: %s\nVersion: %d\nDisk Size: %d bytes\nExtent Size: %d bytes\nArgon2 Time: %d\nArgon2 Memory: %d KiB\nArgon2 Threads: %d\nWrapped Key: %d bytes\nRecovery Key: %d bytes",
			hdr.Magic, hdr.Version, hdr.DiskSizeBytes, hdr.ExtentSize,
			hdr.KDF.Time, hdr.KDF.Memory, hdr.KDF.Threads,
			len(hdr.WrappedMasterKey), len(hdr.WrappedMasterKeyRecovery))
		inspectResult.SetText(info)
		setStatus("Inspect complete")
	})

	inspectForm := container.NewVBox(
		widget.NewLabelWithStyle("Inspect Container", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Container Path:"), inspectPath,
		inspectBtn,
		inspectResult,
	)

	// Change Password section
	passwdPath := widget.NewEntry()
	passwdPath.SetPlaceHolder("/path/to/container.ecd")
	passwdOld := widget.NewPasswordEntry()
	passwdOld.SetPlaceHolder("Current password")
	passwdNew := widget.NewPasswordEntry()
	passwdNew.SetPlaceHolder("New password")

	passwdBtn := widget.NewButtonWithIcon("Change Password", theme.ConfirmIcon(), func() {
		path := passwdPath.Text
		oldPw := passwdOld.Text
		newPw := passwdNew.Text
		if path == "" || oldPw == "" || newPw == "" {
			dialog.ShowError(fmt.Errorf("all fields are required"), w)
			return
		}
		setStatus("Changing password...")
		h, err := cont.OpenWithPassword(path, oldPw)
		if err != nil {
			dialog.ShowError(err, w)
			setStatus("Password change failed")
			return
		}
		defer h.Close()
		if err := h.ChangePassword(newPw); err != nil {
			dialog.ShowError(err, w)
			setStatus("Password change failed")
			return
		}
		setStatus("Password changed!")
		dialog.ShowInformation("Success", "Password changed (master key rewrapped)", w)
	})

	passwdForm := container.NewVBox(
		widget.NewLabelWithStyle("Change Password", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Container Path:"), passwdPath,
		widget.NewLabel("Current Password:"), passwdOld,
		widget.NewLabel("New Password:"), passwdNew,
		passwdBtn,
	)

	// Recovery section
	recoverPath := widget.NewEntry()
	recoverPath.SetPlaceHolder("/path/to/container.ecd")
	recoverKey := widget.NewEntry()
	recoverKey.SetPlaceHolder("XXXX-XXXX-XXXX-...")
	recoverNewPw := widget.NewPasswordEntry()
	recoverNewPw.SetPlaceHolder("New password")

	recoverBtn := widget.NewButtonWithIcon("Recover & Reset Password", theme.WarningIcon(), func() {
		path := recoverPath.Text
		key := recoverKey.Text
		newPw := recoverNewPw.Text
		if path == "" || key == "" || newPw == "" {
			dialog.ShowError(fmt.Errorf("all fields are required"), w)
			return
		}
		setStatus("Recovering...")
		h, err := cont.OpenWithRecovery(path, key)
		if err != nil {
			dialog.ShowError(err, w)
			setStatus("Recovery failed")
			return
		}
		defer h.Close()
		if err := h.ChangePassword(newPw); err != nil {
			dialog.ShowError(err, w)
			setStatus("Recovery failed")
			return
		}
		setStatus("Recovered!")
		dialog.ShowInformation("Success", "Container recovered and password reset", w)
	})

	recoverForm := container.NewVBox(
		widget.NewLabelWithStyle("Recover Container", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Container Path:"), recoverPath,
		widget.NewLabel("Recovery Key:"), recoverKey,
		widget.NewLabel("New Password:"), recoverNewPw,
		recoverBtn,
	)

	// Combine all sections with accordion
	accordion := widget.NewAccordion(
		widget.NewAccordionItem("Create Container", createForm),
		widget.NewAccordionItem("Inspect Container", inspectForm),
		widget.NewAccordionItem("Change Password", passwdForm),
		widget.NewAccordionItem("Recover Container", recoverForm),
	)
	accordion.Open(0)

	return container.NewVScroll(container.NewPadded(accordion))
}

// ─── VHDX Tab ───────────────────────────────────────────────────────

func buildVHDXTab(w fyne.Window, setStatus func(string)) fyne.CanvasObject {
	// Create VHDX
	vhdxPath := widget.NewEntry()
	vhdxPath.SetPlaceHolder("/path/to/disk.vhdx")
	vhdxSizeGB := widget.NewEntry()
	vhdxSizeGB.SetPlaceHolder("10")
	vhdxBlockMB := widget.NewEntry()
	vhdxBlockMB.SetText("4")

	createVHDXBtn := widget.NewButtonWithIcon("Create VHDX", theme.ContentAddIcon(), func() {
		path := vhdxPath.Text
		sizeStr := vhdxSizeGB.Text
		blockStr := vhdxBlockMB.Text
		if path == "" || sizeStr == "" {
			dialog.ShowError(fmt.Errorf("path and size are required"), w)
			return
		}
		sizeGB, err := strconv.ParseUint(sizeStr, 10, 32)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid size: %v", err), w)
			return
		}
		blockMB, err := strconv.ParseUint(blockStr, 10, 32)
		if err != nil {
			blockMB = 4
		}
		setStatus("Creating VHDX...")
		if err := vhdx.Create(path, uint32(sizeGB), uint32(blockMB)); err != nil {
			dialog.ShowError(err, w)
			setStatus("VHDX creation failed")
			return
		}
		setStatus("VHDX created!")
		dialog.ShowInformation("Success", "VHDX file created: "+path, w)
	})
	createVHDXBtn.Importance = widget.HighImportance

	createVHDXForm := container.NewVBox(
		widget.NewLabelWithStyle("Create Blank VHDX", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("VHDX Path:"), vhdxPath,
		widget.NewLabel("Size (GB):"), vhdxSizeGB,
		widget.NewLabel("Block Size (MB):"), vhdxBlockMB,
		createVHDXBtn,
	)

	// Diff VHDX
	diffBase := widget.NewEntry()
	diffBase.SetPlaceHolder("/path/to/base.vhdx")
	diffPath := widget.NewEntry()
	diffPath.SetPlaceHolder("/path/to/child.vhdx")
	diffBlockMB := widget.NewEntry()
	diffBlockMB.SetText("4")

	diffBtn := widget.NewButtonWithIcon("Create Diff VHDX", theme.ContentAddIcon(), func() {
		base := diffBase.Text
		path := diffPath.Text
		blockStr := diffBlockMB.Text
		if base == "" || path == "" {
			dialog.ShowError(fmt.Errorf("base and child paths are required"), w)
			return
		}
		blockMB, err := strconv.ParseUint(blockStr, 10, 32)
		if err != nil {
			blockMB = 4
		}
		setStatus("Creating diff VHDX...")
		if err := vhdx.CreateDiff(path, base, uint32(blockMB)); err != nil {
			dialog.ShowError(err, w)
			setStatus("Diff VHDX creation failed")
			return
		}
		setStatus("Diff VHDX created!")
		dialog.ShowInformation("Success", "Differencing VHDX created: "+path, w)
	})

	diffVHDXForm := container.NewVBox(
		widget.NewLabelWithStyle("Create Differencing VHDX", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Base VHDX:"), diffBase,
		widget.NewLabel("Child VHDX:"), diffPath,
		widget.NewLabel("Block Size (MB):"), diffBlockMB,
		diffBtn,
	)

	accordion := widget.NewAccordion(
		widget.NewAccordionItem("Create VHDX", createVHDXForm),
		widget.NewAccordionItem("Differencing VHDX", diffVHDXForm),
	)
	accordion.Open(0)

	return container.NewVScroll(container.NewPadded(accordion))
}

// ─── Mount Tab ──────────────────────────────────────────────────────

func buildMountTab(w fyne.Window, setStatus func(string)) fyne.CanvasObject {
	// Mount
	mountContPath := widget.NewEntry()
	mountContPath.SetPlaceHolder("/path/to/container.ecd")
	mountPoint := widget.NewEntry()
	mountPoint.SetPlaceHolder("X: or /mnt/crypd")
	mountPassword := widget.NewPasswordEntry()
	mountPassword.SetPlaceHolder("Password")
	mountIdle := widget.NewEntry()
	mountIdle.SetText("900")
	mountCache := widget.NewEntry()
	mountCache.SetText("128")

	mountBtn := widget.NewButtonWithIcon("Mount", theme.MediaPlayIcon(), func() {
		path := mountContPath.Text
		mp := mountPoint.Text
		pw := mountPassword.Text
		if path == "" || mp == "" || pw == "" {
			dialog.ShowError(fmt.Errorf("container path, mount point, and password are required"), w)
			return
		}
		mp = mount.NormalizeMountPoint(mp)
		backend := mount.DefaultBackend()
		if err := mount.CheckAvailable(backend); err != nil {
			dialog.ShowError(fmt.Errorf("mount backend unavailable: %v", err), w)
			return
		}

		idleSec, _ := strconv.Atoi(mountIdle.Text)
		if idleSec <= 0 {
			idleSec = 900
		}
		cacheExt, _ := strconv.Atoi(mountCache.Text)
		if cacheExt <= 0 {
			cacheExt = 128
		}

		setStatus("Mounting...")
		h, err := cont.OpenWithPassword(path, pw)
		if err != nil {
			dialog.ShowError(err, w)
			setStatus("Mount failed: " + err.Error())
			return
		}

		wb := cache.New(h, cacheExt)
		err = backend.Mount(mount.Options{
			ContainerPath: path,
			MountPoint:    mp,
			IdleSeconds:   idleSec,
			CacheExtents:  cacheExt,
			Store:         wb,
			DiskSizeBytes: h.Header.DiskSizeBytes,
			ExtentSize:    h.Header.ExtentSize,
		})
		if err != nil {
			h.Close()
			dialog.ShowError(err, w)
			setStatus("Mount failed: " + err.Error())
			return
		}
		setStatus(fmt.Sprintf("Mounted at %s", mp))
		dialog.ShowInformation("Mounted", "Container mounted at "+mp, w)
	})
	mountBtn.Importance = widget.HighImportance

	mountForm := container.NewVBox(
		widget.NewLabelWithStyle("Mount Container", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Container Path:"), mountContPath,
		widget.NewLabel("Mount Point:"), mountPoint,
		widget.NewLabel("Password:"), mountPassword,
		widget.NewLabel("Idle Timeout (sec):"), mountIdle,
		widget.NewLabel("Cache Extents:"), mountCache,
		mountBtn,
	)

	// Unmount
	unmountPoint := widget.NewEntry()
	unmountPoint.SetPlaceHolder("X: or /mnt/crypd")

	unmountBtn := widget.NewButtonWithIcon("Unmount", theme.MediaStopIcon(), func() {
		mp := unmountPoint.Text
		if mp == "" {
			dialog.ShowError(fmt.Errorf("mount point is required"), w)
			return
		}
		setStatus("Unmounting...")
		if err := mount.DefaultBackend().Unmount(mount.NormalizeMountPoint(mp)); err != nil {
			dialog.ShowError(err, w)
			setStatus("Unmount failed: " + err.Error())
			return
		}
		setStatus("Unmounted " + mp)
		dialog.ShowInformation("Unmounted", "Container unmounted from "+mp, w)
	})

	unmountForm := container.NewVBox(
		widget.NewLabelWithStyle("Unmount Container", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Mount Point:"), unmountPoint,
		unmountBtn,
	)

	accordion := widget.NewAccordion(
		widget.NewAccordionItem("Mount", mountForm),
		widget.NewAccordionItem("Unmount", unmountForm),
	)
	accordion.Open(0)

	return container.NewVScroll(container.NewPadded(accordion))
}
