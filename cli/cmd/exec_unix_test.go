//go:build !windows

package cmd

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

func TestChildExitStatusIsPassedThrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for script, want := range map[string]int{"exit 7": 7, "kill -TERM $$": 128 + 15} {
		// A cancellable context selects the forwarding path instead of replacing the test process.
		err := runChild(ctx, exec.CommandContext(ctx, "sh", "-c", script))
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exitCode(exit) != want {
			t.Fatalf("%q: got %v, want exit code %d", script, err, want)
		}
	}
}
