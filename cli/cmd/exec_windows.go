//go:build windows

package cmd

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
)

func runChild(_ context.Context, child *exec.Cmd) error {
	// Ctrl+C and Ctrl+Break reach every process on the console, including the child.
	// Keep the CLI alive until the child decides how to exit.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	return child.Run()
}

func exitCode(exit *exec.ExitError) int { return exit.ExitCode() }
