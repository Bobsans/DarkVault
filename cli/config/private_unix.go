//go:build !windows

package config

import "os"

func privateTemp(dir string) (*os.File, error) {
	// CreateTemp creates files with 0600 regardless of the directory's default permissions.
	return os.CreateTemp(dir, ".config-*.tmp")
}
