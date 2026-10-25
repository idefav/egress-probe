//go:build !windows

package server

import (
	"os"
	"path/filepath"
)

func replaceAuthFile(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
