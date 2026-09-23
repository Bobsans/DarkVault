package cmd

import (
	"runtime/debug"
	"strings"
)

// Release builds set Version to release:<version>+<commit> using -ldflags -X.
// The prefix also lets the package verifier inspect cross-built executables.
var Version = "0.0.0-dev"

func buildVersion() string {
	if strings.HasPrefix(Version, "release:") {
		return strings.TrimPrefix(Version, "release:")
	}
	commit := ""
	modified := false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				commit = setting.Value
			}
			if setting.Key == "vcs.modified" {
				modified = setting.Value == "true"
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}
	if modified {
		commit += ".dirty"
	}
	return Version + "+" + commit
}
