//go:build !windows

package vhdx

import "errors"

func Create(path string, sizeGB, blockMB uint32) error   { return errors.New("windows only") }
func CreateDiff(path, base string, blockMB uint32) error { return errors.New("windows only") }
func Attach(path string) error                           { return errors.New("windows only") }
func Detach(path string) error                           { return errors.New("windows only") }
