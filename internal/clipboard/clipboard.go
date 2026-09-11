// Package clipboard copies text to the system clipboard using the
// platform's own command-line tool, so the terminal/GUI never depends on
// external libraries.
package clipboard

import (
	"bytes"
	"errors"
	"os/exec"
	"runtime"
)

// ErrNoTool is returned when no platform clipboard command is available.
var ErrNoTool = errors.New("no clipboard tool found (install wl-clipboard, xclip, xsel, or run in a desktop session)")

// Copy places text on the clipboard. The command is launched with text on
// stdin, so special characters need no quoting.
func Copy(text string) error {
	cmd, err := command()
	if err != nil {
		return err
	}
	cmd.Stdin = bytes.NewBufferString(text)
	return cmd.Run()
}

func command() (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("pbcopy"), nil
	case "windows":
		return exec.Command("powershell", "-NoProfile", "-Command",
			"Set-Clipboard -Value ([Console]::In.ReadToEnd())"), nil
	}
	for _, tool := range [][]string{
		{"wl-copy"},
		{"xclip", "-selection", "clipboard"},
		{"xsel", "--clipboard", "--input"},
	} {
		if _, err := exec.LookPath(tool[0]); err == nil {
			return exec.Command(tool[0], tool[1:]...), nil
		}
	}
	return nil, ErrNoTool
}
