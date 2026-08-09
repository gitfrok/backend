//go:build linux

package main

import "syscall"

const fuseSuperMagic = 0x65735546

type systemMount struct{}

func (systemMount) Check(root string) error {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(root, &stats); err != nil {
		return err
	}
	if uint64(stats.Type) == fuseSuperMagic {
		return ErrFUSERepositoryRoot
	}
	return nil
}
