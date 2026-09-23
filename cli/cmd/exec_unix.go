//go:build !windows

package cmd

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func runChild(ctx context.Context, child *exec.Cmd) error {
	if child.Err != nil {
		return child.Err
	}
	// With the real terminal and no cancellation, replace this process so the program
	// receives signals and reports its exit status directly.
	if ctx.Done() == nil && child.Stdin == os.Stdin && child.Stdout == os.Stdout && child.Stderr == os.Stderr {
		return syscall.Exec(child.Path, child.Args, child.Env)
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	if err := child.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	for {
		select {
		case s := <-signals:
			_ = child.Process.Signal(s)
		case err := <-done:
			return err
		}
	}
}

// exitCode follows the shell convention: a program killed by signal N exits with 128+N.
func exitCode(exit *exec.ExitError) int {
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return exit.ExitCode()
}
