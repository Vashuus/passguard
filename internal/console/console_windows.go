//go:build windows

// Package console detects how the process was launched, so a double click
// in Explorer can open the GUI instead of a terminal interface.
package console

import (
	"syscall"
	"unsafe"
)

// ProcessCount returns how many processes share the current console.
// Explorer double-clicks yield 1; running from cmd/PowerShell yields 2+;
// no console at all yields 0.
func ProcessCount() uint32 {
	mod := syscall.NewLazyDLL("kernel32.dll")
	p := mod.NewProc("GetConsoleProcessList")
	if p.Find() != nil {
		return 0
	}
	var head [4]uint32
	r, _, _ := p.Call(uintptr(unsafe.Pointer(&head[0])), uintptr(len(head)))
	return uint32(r)
}

// AutoGUI reports whether the binary was launched without a shell
// attached (double-clicked from Explorer).
func AutoGUI() bool {
	return ProcessCount() < 2
}
