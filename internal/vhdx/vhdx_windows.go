//go:build windows

package vhdx

import "github.com/Microsoft/go-winio/vhd"

func Create(path string, sizeGB, blockMB uint32) error {
	return vhd.CreateVhdx(path, sizeGB, blockMB)
}

func CreateDiff(path, base string, blockMB uint32) error {
	return vhd.CreateDiffVhd(path, base, blockMB)
}

func Attach(path string) error {
	return vhd.AttachVhd(path)
}

func Detach(path string) error {
	return vhd.DetachVhd(path)
}
