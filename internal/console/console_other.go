//go:build !windows

// Package console detects how the process was launched, so a double click
// in Explorer can open the GUI instead of a terminal interface.
package console

// AutoGUI is disabled on non-Windows platforms: the terminal UI is the
// default there.
func AutoGUI() bool { return false }
