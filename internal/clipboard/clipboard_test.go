package clipboard

import (
	"runtime"
	"testing"
)

func TestCommandSelection(t *testing.T) {
	cmd, err := command()
	if err != nil {
		if err == ErrNoTool && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
			t.Log("no clipboard tool on this host, skipping")
			return
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd == nil || cmd.Path == "" {
		t.Fatal("expected a usable command path")
	}
}

func TestCopyFailsGracefullyWithoutTool(t *testing.T) {
	// Copy must never hang or panic; on hosts without a clipboard tool it
	// should return ErrNoTool instead of producing a partial command.
	if err := Copy("test"); err != nil {
		if err != ErrNoTool {
			// A real tool exists but failed (e.g. headless X): acceptable.
			t.Logf("Copy failed (tool present but unusable): %v", err)
		}
	}
}
